```sh
# Example: build on Ubuntu 16.04 =>

./http-new helloworld
echo "Hello World!" > ./applications/helloworld/resources/static/index.html

./http-make helloworld
./http-run helloworld


# Or build Docker image =>

DOCKER=y ./http-make helloworld
docker run -it -p 8080:80 --rm <your-repo>/helloworld 

```
