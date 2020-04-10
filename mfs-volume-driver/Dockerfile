FROM golang:1.13-buster AS build

WORKDIR /mvd

COPY go.mod go.sum ./
RUN go mod verify
RUN go mod download

COPY . .
RUN go build -v -tags netgo -installsuffix netgo -ldflags '-d -s -w' -o /mfs-volume-driver ./...

# TODO make proper tagged releases (with binaries) and consume those instead
FROM alpine:3.11

COPY --from=build /mfs-volume-driver /usr/local/bin/

CMD ["mfs-volume-driver"]
