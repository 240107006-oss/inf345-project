FROM eclipse-temurin:21-jdk-jammy
WORKDIR /app
COPY pom.xml .
COPY Main.java .
RUN javac Main.java
USER 1000:1000
CMD ["java", "Main"]