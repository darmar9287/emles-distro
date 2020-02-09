FROM openjdk:8u131-jdk-alpine

WORKDIR /usr/local/bin/

COPY ./target/emles_oauth_server-0.0.1-SNAPSHOT.jar webapp.jar

CMD ["java", "-jar","webapp.jar"]