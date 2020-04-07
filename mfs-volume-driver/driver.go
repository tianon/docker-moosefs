package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/volume"
	"github.com/moby/sys/mountinfo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	driverName        = "mfs"
	labelNamespace    = "xyz.tianon." + driverName + "-volume-driver"
	labelName         = labelNamespace + ".volume-name"
	labelCreated      = labelNamespace + ".volume-created"
	labelOptionPrefix = labelNamespace + ".volume-options."
)

type mfsVolume struct {
	d       *mfsVolumeDriver
	Name    string            `json:"name,omitempty"`
	Options map[string]string `json:"options,omitempty"`
	Created string            `json:"created,omitempty"`
}

func (v mfsVolume) mountpoint() string {
	if mountpoint := v.Options["mountpoint"]; mountpoint != "" {
		return mountpoint
	}
	return filepath.Join(v.d.defaultMountpointBase, v.Name)
}

func (v mfsVolume) shouldMkdir() bool {
	switch v.Options["mkdir"] {
	case "":
		if v.Options["mountpoint"] == "" {
			return true
		}
	case "true":
		return true
	}
	return false
}

func (v mfsVolume) mkdir() error {
	if !v.shouldMkdir() {
		return nil
	}
	return os.MkdirAll(v.mountpoint(), 0755)
}

func (v mfsVolume) shouldRmdir() bool {
	switch v.Options["rmdir"] {
	case "":
		return v.shouldMkdir()
	case "true":
		return true
	}
	return false
}

func (v mfsVolume) rmdir() error {
	if !v.shouldRmdir() {
		return nil
	}
	return os.Remove(v.mountpoint())
}

func (v mfsVolume) volume() *volume.Volume {
	return &volume.Volume{
		Name:       v.Name,
		Mountpoint: v.mountpoint(),
		CreatedAt:  v.Created,
		Status: map[string]interface{}{
			"config": map[string]interface{}{
				"mkdir": v.shouldMkdir(),
				"rmdir": v.shouldRmdir(),
			},
			"mounted":   v.isMounted(),
			"container": v.containerMeta(),
			"mfsmount":  v.mfsmountCmd(),
		},
	}
}

func (v mfsVolume) isMounted() bool {
	mountpoint := v.mountpoint()
	// TODO do we need to Abs and EvalSymlinks ?

	if ok, err := mountinfo.Mounted(mountpoint); err != nil {
		logrus.Error(err)
		return false
	} else if !ok {
		return false
	}

	// "Socket not connected" (bad/stale mount)
	if _, err := os.Lstat(mountpoint); err != nil {
		return false
	}

	// if the mfsmount ".stats" and ".random" pseudo-files exist, we're very likely successfully mounted
	if _, err := os.Lstat(filepath.Join(mountpoint, ".stats")); err != nil {
		return false
	}
	if _, err := os.Lstat(filepath.Join(mountpoint, ".random")); err != nil {
		return false
	}

	// TODO check for our container too?

	return true
}

type mfsContainerMeta struct {
	Name     string            `json:"name,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

func (v mfsVolume) containerName() string {
	return strings.Join([]string{
		driverName,
		"volume-mnt",
		v.Name,
	}, "-")
}

func (v mfsVolume) containerMeta() mfsContainerMeta {
	meta := mfsContainerMeta{
		Name: v.containerName(),

		// TODO Hostname

		Labels: map[string]string{
			labelName:    v.Name,
			labelCreated: v.Created,
		},
	}

	for oK, oV := range v.Options {
		meta.Labels[labelOptionPrefix+oK] = oV
	}

	return meta
}

func (v mfsVolume) mfsmountCmd() []string {
	cmd := []string{
		"mfsmount", "-f",
		"-o", "auto_unmount",
		"-o", "nonempty",
	}

	opts := map[string]string{}
	for key, val := range v.d.defaultOpts {
		opts[key] = val
	}
	for key, val := range v.Options {
		switch key {
		case "mountpoint", "mkdir", "rmdir": // ignore our options
		default:
			opts[key] = val
		}
	}
	for key, val := range v.Options {
		if val != "" {
			cmd = append(cmd, "-o", key+"="+val)
		} else {
			cmd = append(cmd, "-o", key)
		}
	}

	return cmd
}

func (v mfsVolume) ensureMounted() error {
	if v.isMounted() {
		return nil
	}
	if err := v.unmount(); err != nil {
		return err
	}

	if err := v.mkdir(); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}

	ctx := context.TODO()
	docker := v.d.docker
	meta := v.containerMeta()
	name := meta.Name

	// force remove any old container (since if it exists, it's in a bad state per our "isMounted" check)
	if err := docker.ContainerRemove(ctx, name, types.ContainerRemoveOptions{Force: true}); err != nil && !client.IsErrNotFound(err) {
		return err
	}

	dir := v.mountpoint()
	if res, err := docker.ContainerCreate(ctx, &container.Config{
		// TODO Hostname
		Image: v.d.dockerImage,
		Cmd: append([]string{"sh", "-euc", `
			# get the last parameter (our mount target)
			for dir; do :; done
			# umount (stale mount) if necessary ("transport endpoint not connected")
			if ! stat "$dir" > /dev/null 2>&1 || mountpoint "$dir" > /dev/null; then
				fusermount -u "$dir" ||
				umount "$dir" ||
				umount -f "$dir" ||
				umount -l "$dir"
			fi
			exec "$@"
		`, "--"}, append(v.mfsmountCmd(), dir)...),
		WorkingDir:  filepath.Dir(dir),
		StopTimeout: (func() *int { b := 120; return &b })(),
		Labels:      meta.Labels,
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode(v.d.dockerNetwork),
		RestartPolicy: container.RestartPolicy{
			Name: "always",
		},
		CapAdd: []string{"SYS_ADMIN"},
		Resources: container.Resources{
			Devices: []container.DeviceMapping{
				{
					PathOnHost:        "/dev/fuse",
					PathInContainer:   "/dev/fuse",
					CgroupPermissions: "rwm",
				},
			},
		},
		Mounts: []mount.Mount{
			{
				Type:   "bind",
				Source: filepath.Dir(dir), // TODO find a better solution than mounting the parent directory for being able to clean up stale mounts
				Target: filepath.Dir(dir),
				BindOptions: &mount.BindOptions{
					Propagation: "rshared",
				},
			},
		},
		Init: (func() *bool { b := true; return &b })(),
	}, &network.NetworkingConfig{}, name); err != nil {
		return err
	} else if len(res.Warnings) > 0 {
		logrus.WithFields(logrus.Fields{
			"id":       res.ID,
			"name":     name,
			"warnings": strings.Join(res.Warnings, "\n"),
		}).Warn("container created (with warnings)")
	} else {
		logrus.WithFields(logrus.Fields{
			"id":   res.ID,
			"name": name,
		}).Info("container created")
	}

	if err := docker.ContainerStart(ctx, name, types.ContainerStartOptions{}); err != nil {
		return err
	} else {
		logrus.WithFields(logrus.Fields{
			"name": name,
		}).Info("container started")
	}

	// give it a little time to start up and get connected and double check that "isMounted" returns true
	timeo := time.After(25 * time.Second) // TODO configurable startup timeout? ("mfsdelayedinit" plays a role here)
	// at ~20 seconds we should get "can't resolve master hostname and/or portname (foo:9421)" on a bad mfsmaster value
	// at ~120 seconds, the client gives up ("context deadline exceeded")
	tick := time.Tick(100 * time.Millisecond)
isMountedLoop:
	for {
		if v.isMounted() {
			return nil
		}
		// TODO check if container is restarting? (so we can bail earlier)
		select {
		case <-timeo:
			// TODO propagate to the error message that this was a timeout
			break isMountedLoop
		case <-tick:
		}
	}

	if !v.isMounted() {
		if logsReadCloser, err := docker.ContainerLogs(ctx, name, types.ContainerLogsOptions{
			ShowStdout: true,
			ShowStderr: true,
		}); err == nil {
			defer logsReadCloser.Close()
			if logs, err := ioutil.ReadAll(logsReadCloser); err == nil {
				return v.d.err("failed to start volume %q:\n%s", v.Name, string(logs))
			}
		}
		return v.d.err("failed to start volume %q (unknown issue)", v.Name)
	}

	return nil
}

func (v mfsVolume) unmount() error {
	ctx := context.TODO()
	docker := v.d.docker

	// remove all containers with a matching "volume-name" label
	filters := filters.NewArgs()
	filters.Add("label", labelName+"="+v.Name)
	if ctrs, err := docker.ContainerList(ctx, types.ContainerListOptions{
		All:     true,
		Filters: filters,
	}); err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	} else {
		for _, ctr := range ctrs {
			if err := docker.ContainerStop(ctx, ctr.ID, nil); err != nil && !client.IsErrNotFound(err) {
				return fmt.Errorf("failed to stop container %s: %w", ctr.ID, err)
			}
			if err := docker.ContainerRemove(ctx, ctr.ID, types.ContainerRemoveOptions{Force: true}); err != nil && !client.IsErrNotFound(err) {
				return fmt.Errorf("failed to remove container %s: %w", ctr.ID, err)
			}
		}
	}

	// remove any leftover container matching our desired container name
	name := v.containerName()
	if err := docker.ContainerStop(ctx, name, nil); err != nil && !client.IsErrNotFound(err) {
		return fmt.Errorf("failed to stop container %s: %w", name, err)
	}
	if err := docker.ContainerRemove(ctx, name, types.ContainerRemoveOptions{Force: true}); err != nil && !client.IsErrNotFound(err) {
		return fmt.Errorf("failed to remove container %s: %w", name, err)
	}

	/*
		// TODO these all require CAP_SYS_ADMIN, which we do not have haha whoops
		// umount system call as well, just to be sure (in case our mount crashed, etc)
		if err := unix.Unmount(v.mountpoint(), 0); err != nil {
			return fmt.Errorf("failed to unmount: %w", err)
		}
		if err := unix.Unmount(v.mountpoint(), unix.MNT_FORCE); err != nil {
			return fmt.Errorf("failed to unmount -f: %w", err)
		}
		if err := unix.Unmount(v.mountpoint(), unix.MNT_DETACH); err != nil {
			return fmt.Errorf("failed to unmount -l: %w", err)
		}
	*/

	if err := v.rmdir(); err != nil && !errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("failed to rmdir: %w", err)
	}

	return nil
}

type mfsVolumeDriver struct {
	Volumes map[string]*mfsVolume `json:"volumes"`

	name                  string
	stateDir              string
	SocketFile            string
	defaultMountpointBase string
	mutex                 *sync.Mutex

	defaultOpts map[string]string

	docker        *client.Client
	dockerImage   string
	dockerNetwork string
}

func (d *mfsVolumeDriver) loadState() error {
	logrus.Info("loading state")

	ctx := context.TODO()

	filters := filters.NewArgs()
	filters.Add("label", labelName)
	if ctrs, err := d.docker.ContainerList(ctx, types.ContainerListOptions{
		All:     true,
		Filters: filters,
	}); err != nil {
		return err
	} else {
		for _, ctr := range ctrs {
			v := d.newVolume()
			for lK, lV := range ctr.Labels {
				switch lK {
				case labelName:
					v.Name = lV
				case labelCreated:
					v.Created = lV
				default:
					if strings.HasPrefix(lK, labelOptionPrefix) {
						v.Options[lK[len(labelOptionPrefix):]] = lV
					}
				}
			}
			if v.Name != "" {
				d.Volumes[v.Name] = v
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"volumes": len(d.Volumes),
	}).Info("loaded state")

	return nil
}

func newMfsVolumeDriver(defaultOpts map[string]string) (*mfsVolumeDriver, error) {
	d := &mfsVolumeDriver{
		Volumes: map[string]*mfsVolume{},

		mutex: &sync.Mutex{},

		defaultOpts:   defaultOpts,
		dockerImage:   os.Getenv("MFS_DOCKER_IMAGE"),
		dockerNetwork: os.Getenv("MFS_DOCKER_NETWORK"),
	}

	if docker, err := client.NewClientWithOpts(client.FromEnv); err != nil {
		return nil, d.err("failed to connect to Docker: %w", err)
	} else if dockerVersion, err := docker.ServerVersion(context.TODO()); err != nil {
		return nil, d.err("failed to connect to Docker: %w", err)
	} else {
		logrus.WithFields(logrus.Fields{
			"version":       dockerVersion.Version,
			"apiVersion":    dockerVersion.APIVersion,
			"os":            dockerVersion.Os,
			"arch":          dockerVersion.Arch,
			"kernelVersion": dockerVersion.KernelVersion,
		}).Info("connected to Docker")
		d.docker = docker
	}

	// TODO allow passing a container name to scrape these from instead (so we can use https://docs.docker.com/engine/reference/commandline/service_create/#template-example to set these to the values of our plugin service container and match the right image digest automatically)
	if d.dockerImage == "" {
		return nil, d.err("missing MFS_DOCKER_IMAGE environment variable")
	}
	if d.dockerNetwork == "" {
		return nil, d.err("missing MFS_DOCKER_NETWORK environment variable")
	}

	d.stateDir = filepath.Join("/run/docker/plugins", driverName)
	if err := os.MkdirAll(d.stateDir, 0755); err != nil {
		return nil, err
	}
	d.SocketFile = filepath.Join(d.stateDir, driverName+".sock")

	d.defaultMountpointBase = filepath.Join(d.stateDir, "mnt")
	if err := os.MkdirAll(d.defaultMountpointBase, 0755); err != nil {
		return nil, err
	}

	if err := d.loadState(); err != nil {
		return nil, err
	}

	for _, v := range d.Volumes {
		if err := v.ensureMounted(); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func (d *mfsVolumeDriver) newHandler() *volume.Handler {
	return volume.NewHandler(d)
}

func (d *mfsVolumeDriver) err(str string, args ...interface{}) error {
	return fmt.Errorf(driverName+" "+str, args...)
}

func (d *mfsVolumeDriver) exists(name string) bool {
	_, ok := d.Volumes[name]
	return ok
}

func (d *mfsVolumeDriver) existsErr(name string) error {
	if !d.exists(name) {
		return d.err("volume %q: does not exist", name)
	}
	return nil
}

func (d *mfsVolumeDriver) newVolume() *mfsVolume {
	return &mfsVolume{
		d:       d,
		Options: map[string]string{},
		Created: time.Now().Format(time.RFC3339Nano),
	}
}

func (d *mfsVolumeDriver) Create(req *volume.CreateRequest) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	name := req.Name
	logrus.WithFields(logrus.Fields{
		"name": name,
		"opts": req.Options,
	}).Info("create request")

	if d.exists(name) {
		return d.err("volume %q: already exists", name)
	}

	v := d.newVolume()
	v.Name = name
	v.Options = req.Options

	if err := v.ensureMounted(); err != nil {
		v.unmount() // cleanup, if possible/necessary
		return err
	}

	d.Volumes[name] = v

	return nil
}

func (d *mfsVolumeDriver) List() (*volume.ListResponse, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	logrus.Info("list request")

	res := &volume.ListResponse{
		Volumes: []*volume.Volume{},
	}
	for _, v := range d.Volumes {
		res.Volumes = append(res.Volumes, v.volume())
	}

	return res, nil
}

func (d *mfsVolumeDriver) Get(req *volume.GetRequest) (*volume.GetResponse, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	name := req.Name
	logrus.WithFields(logrus.Fields{
		"name": name,
	}).Info("get request")

	if err := d.existsErr(name); err != nil {
		return nil, err
	}
	v := d.Volumes[name]

	return &volume.GetResponse{
		Volume: v.volume(),
	}, nil
}

func (d *mfsVolumeDriver) Remove(req *volume.RemoveRequest) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	name := req.Name
	logrus.WithFields(logrus.Fields{
		"name": name,
	}).Info("remove request")

	if err := d.existsErr(name); err != nil {
		return err
	}
	v := d.Volumes[name]

	if err := v.unmount(); err != nil {
		return err
	}

	delete(d.Volumes, name)

	return nil
}

func (d *mfsVolumeDriver) Path(req *volume.PathRequest) (*volume.PathResponse, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	name := req.Name
	logrus.WithFields(logrus.Fields{
		"name": name,
	}).Info("path request")

	if err := d.existsErr(name); err != nil {
		return nil, err
	}
	v := d.Volumes[name]

	return &volume.PathResponse{
		Mountpoint: v.mountpoint(),
	}, nil
}

func (d *mfsVolumeDriver) Mount(req *volume.MountRequest) (*volume.MountResponse, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	name := req.Name
	logrus.WithFields(logrus.Fields{
		"name": name,
	}).Info("mount request")

	if err := d.existsErr(name); err != nil {
		return nil, err
	}
	v := d.Volumes[name]

	if err := v.ensureMounted(); err != nil {
		return nil, err
	}

	return &volume.MountResponse{
		Mountpoint: v.mountpoint(),
	}, nil
}

func (d *mfsVolumeDriver) Unmount(req *volume.UnmountRequest) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	name := req.Name
	logrus.WithFields(logrus.Fields{
		"name": name,
	}).Info("unmount request")

	if err := d.existsErr(name); err != nil {
		return err
	}

	return nil
}

func (d *mfsVolumeDriver) Capabilities() *volume.CapabilitiesResponse {
	logrus.Info("capabilities request")

	return &volume.CapabilitiesResponse{
		Capabilities: volume.Capability{
			Scope: "local",
		},
	}
}
