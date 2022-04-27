**Description**

 - This is a simple Python microservice(s) to execute CI directly on a VM. 
 - It was designed to receive a webhook from Github or Bitbucket
 - It will process that webhook, pull the code, and execute a Docker build.

**Overview**

 - The application consist of three microservices: 

| microservice      | description                            
| ------------- | -------------------------------------- 
| nginx      | the proxy that terminates ssl and proxies to the api microservice
| api      | accepts the webhook from Github or Bitbucket, processes it, and writes a yaml config for the ci microservice
| ci        | reads yaml. tests, builds, and optionally scans the container for security vulnerabilities

The CI microservice was designed to send the results to a user's account on Elasticdev.  This can be bypassed and run standalone by not setting the environmental variable "QUEUE_HOST".

**Build and Run**

  - Each microservice is separated into their own folder with a Dockerfile used for building the image.
  - Create ".env", using the "docker/run/dot-env-sample" as a starting point.
  - Execute docker builds and deploy through docker-compose

    ```
    cd docker/run
    docker-compose build && docker-compose up -d
    ```
