FROM golang:1.22-alpine AS build
WORKDIR /src
# go.sum is optional in the build context: the glob keeps the build
# working when only go.mod is present, and `go mod download` resolves
# and records the required hashes either way. (Running `go mod tidy`
# before the sources are copied would prune the requirements, so the
# committed go.mod/go.sum pair stays the lock instead.)
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/control-plane .

FROM alpine:3.20
RUN adduser -D kronos
COPY --from=build /out/control-plane /usr/local/bin/control-plane
USER kronos
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["control-plane"]
