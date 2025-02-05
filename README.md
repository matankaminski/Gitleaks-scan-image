You can pull the image and work directly with it instead of building it first with the command:

   "docker pull ghcr.io/matankaminski/gitleaks-scan-image:v1.0"
   
Aotherwise you can build and run the image with the instruction below.
Instruction for running the image:

1. Build the Docker Image (if not already built): If you haven't built your Docker image yet, use the following command to build it from the Dockerfile. Make sure you are in the directory containing your Dockerfile:
 
    "docker build -t <your_image_name> ."

Replace your_image_name with a name you want to assign to your Docker image.
The flag -t gives the container a name like: "docker build -t gitleaks-container ."

2. Run the Docker Container: Use the docker run command to run the container with the image. In this case, we will mount the current working directory to /code/ in the container to ensure that files are accessible from inside the container.
Here’s the command to run the container:

    docker run -v "<path_of_your_directory_to_scan>:/code" your_image_name

Replace your_image_name with the name of your Docker image.

3. If you need to run specific commands inside the container, such as gitleaks, you can either:
 Run them directly by the run command above as the default command is:
    gitleaks detect --no-git --report-path /code/output.json /code/.

 Run them with your arguments:
    docker run -v "<path_of_your_directory_to_scan>:/code" your_image_name arg1 arg2...

Node: you need to specify in your command to gitleaks to creat a JSON format file named "output.json" in /code/ other wish it will raise an error.

If everything when as planned, after running the image you will recive info on the secrets Gitleaks found printed in the console like:
{
  "findings":[
  {
      "filename":"bad-vars.tf",
      "line_range":"11-11",
      "description":"Identified a pattern that may indicate AWS ..."
    },
    {
      "filename":"README.md",
      "line_range":"13-13",
      "description":"Identified a pattern that may indicate AWS ..."
    }
  ]
}
