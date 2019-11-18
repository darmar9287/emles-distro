FROM maven:3.6.1-jdk-8

WORKDIR /app

COPY ./pom.xml ./

RUN mvn dependency:go-offline -B

COPY . .

#CMD ["mvn", "spring-boot:run"]