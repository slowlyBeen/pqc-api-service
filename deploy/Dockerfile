# ========================================
# Stage 1: 빌드 스테이지
# ========================================
FROM gradle:8.5-jdk17 AS builder

WORKDIR /app

# Gradle 캐시 최적화를 위한 의존성 다운로드
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
RUN gradle dependencies --no-daemon || true

# 소스 코드 복사 및 빌드
COPY src ./src
RUN gradle bootJar --no-daemon -x test

# ========================================
# Stage 2: 실행 스테이지
# ========================================
FROM eclipse-temurin:17-jre-alpine

LABEL maintainer="slowlybeen"
LABEL description="PQC API Service with ML-KEM/ML-DSA support"

WORKDIR /app

# 보안: non-root 유저 생성
RUN addgroup -S pqcgroup && adduser -S pqcuser -G pqcgroup

# JAR 파일 복사
COPY --from=builder /app/build/libs/pqc-api-service-*.jar app.jar

# 소유권 변경
RUN chown -R pqcuser:pqcgroup /app

# 유저 전환
USER pqcuser

# 헬스체크 설정
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# JVM 옵션 및 실행
ENTRYPOINT ["java", \
    "-XX:+UseG1GC", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+HeapDumpOnOutOfMemoryError", \
    "-XX:HeapDumpPath=/app/logs", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]

EXPOSE 8080