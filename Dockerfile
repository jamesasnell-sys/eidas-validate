# Build stage. Kept separate so the runtime image carries no compiler,
# no Maven, and no build cache.
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /build

# Dependency resolution is cached as its own layer, so ordinary source
# changes do not re-download the DSS tree on every build.
COPY pom.xml .
COPY core/pom.xml core/pom.xml
COPY api/pom.xml api/pom.xml
RUN mvn -q -B dependency:go-offline -DskipTests || true

COPY core/src core/src
COPY api/src api/src

# Tests run in the build. A container that cannot pass them should not
# reach a deployment.
RUN mvn -q -B clean package

FROM eclipse-temurin:21-jre-alpine AS runtime

# su-exec drops privileges in the entrypoint once the mounted disk has been
# made writable. Nothing else in the image needs it.
RUN apk add --no-cache su-exec

# The service parses untrusted input from anyone, so it does not run as
# root. The entrypoint starts as root only long enough to prepare the
# disk, then hands over to this user.
RUN addgroup -S eidas && adduser -S eidas -G eidas

WORKDIR /app
COPY --from=build /build/api/target/eidas-validate-api-*.jar /app/eidas-validate.jar

# The entrypoint is written here rather than committed as a .sh file. A shell
# script checked out on Windows carries CRLF endings, which makes the shebang
# read as an interpreter named "/bin/sh\r" and stops the container starting.
# Generating it inside the build container gives LF regardless of the host,
# without asking git to rewrite anything in the repository.
#
# What it does: a mounted persistent disk arrives owned by root, so a
# container that has already dropped to a non-root user cannot write to it.
# Starting as root, fixing ownership, then dropping privileges is the way
# round that. Running the whole service as root would be worse.
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -e' \
  'CACHE_DIR="${TSL_CACHE_DIR:-/var/data/tsl-cache}"' \
  'mkdir -p "$CACHE_DIR"' \
  'chown -R eidas:eidas "$CACHE_DIR" 2>/dev/null || true' \
  'if ! su-exec eidas test -w "$CACHE_DIR"; then' \
  '  echo "WARNING: $CACHE_DIR is not writable by the service user."' \
  '  echo "WARNING: Trusted list data will not survive a restart, and every"' \
  '  echo "WARNING: cold start will perform a full refresh before it can answer."' \
  'fi' \
  'exec su-exec eidas java $JAVA_OPTS -jar /app/eidas-validate.jar' \
  > /app/docker-entrypoint.sh \
  && chmod +x /app/docker-entrypoint.sh \
  && chown -R eidas:eidas /app

# Cache lives on a persistent disk mounted here. Without one the directory
# is ordinary container storage and does not survive a restart, which the
# entrypoint warns about rather than hiding.
ENV TSL_CACHE_DIR=/var/data/tsl-cache

# Sized against a 512 MB container, which is what both the free and starter
# instances provide. Measured: a full trusted list refresh settles at roughly
# 380 MB resident with these values, against roughly 470 MB when the heap is
# left at 300 MB and the metaspace uncapped. Headroom matters more than
# throughput here, because exceeding the container limit is not a slow
# request, it is a killed process.
ENV JAVA_OPTS="-Xmx192m -Xss512k -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m -XX:MaxDirectMemorySize=32m -XX:+UseSerialGC -XX:+ExitOnOutOfMemoryError"

EXPOSE 8080

ENTRYPOINT ["/app/docker-entrypoint.sh"]
