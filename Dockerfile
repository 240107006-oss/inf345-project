FROM eclipse-temurin:21-jdk-jammy AS builder
WORKDIR /app
COPY pom.xml .
COPY Main.java .
RUN javac Main.java

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

COPY --from=builder /app/*.class ./

USER 1000:1000
CMD ["java", "Main"]

