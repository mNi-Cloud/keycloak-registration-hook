FROM gradle:7.4-jdk17-alpine AS builder

WORKDIR /app
COPY . .
USER root
RUN gradle jar

FROM bitnami/keycloak:25.0.4-debian-12-r0

COPY --from=builder /app/build/libs/*.jar /opt/bitnami/keycloak/providers/reghook.jar