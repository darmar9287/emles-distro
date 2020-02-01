FROM maven:3.6.1-jdk-8

WORKDIR /app

COPY ./pom.xml ./

RUN mvn clean package

COPY . .

CMD ["java", "-jar", "target/emles_oauth_server-0.0.1-SNAPSHOT.jar"]