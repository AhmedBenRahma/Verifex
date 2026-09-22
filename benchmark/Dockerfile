# Builds OWASP BenchmarkJava into a WAR and serves it on Tomcat 9.
#
# Stage 1 packages the WAR with Maven. Stage 2 drops it into a standard
# Tomcat, which auto-deploys it at /benchmark. Serving on plain HTTP :8080
# inside the container is fine for scanning - the test-case ids in the URLs
# (BenchmarkTestNNNNN) are what the labeller keys on, regardless of scheme.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
RUN git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git .
RUN mvn -q -DskipTests package
# The build produces target/benchmark.war (or a versioned war); normalise it.
RUN cp "$(ls target/*.war | head -n1)" /benchmark.war

FROM tomcat:9.0-jre17-temurin
# Serve the app at /benchmark
COPY --from=build /benchmark.war /usr/local/tomcat/webapps/benchmark.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
