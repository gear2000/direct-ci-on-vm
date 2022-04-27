#!/usr/bin/python

import os
import yaml
from time import sleep
from time import time
from edreporthelper.utilities import run_cmds
from edreporthelper.utilities import git_clone_repo

def build_image(dockerfile="Dockerfile"):

    """
    wrapper around shellout to build a docker image

    Parameters
    -------
    dockerfile - str
       the "Dockerfile" to perform the docker build
    Returns
    -------
    results - dict
       the results of the docker build process including
       the log and status
    """

    repo_dir = os.environ["DOCKER_BUILD_DIR"]
    repository_uri = os.environ["REPOSITORY_URI"]
    tag = os.environ["COMMIT_HASH"][0:6]
    cmds = []
    cmds.append("cd {} && docker build -t {}:{} . -f {}".format(repo_dir,repository_uri,tag,dockerfile))
    cmds.append("cd {} && docker build -t {}:latest . -f {}".format(repo_dir,repository_uri,dockerfile))

    os.environ["TIMEOUT"] = str(os.environ.get("DOCKER_BUILD_TIMEOUT",1800))

    try:
        results = run_cmds(cmds)
    except:
        results = {"status":False}
        results["log"] = "TIMED OUT building image"

    return results

def scan_image():

    """
    wrapper around shellout to scan docker image

    Returns
    -------
    results - dict
       the results of the image scan including
       the log and status
    """

    trivy_exists = None

    #if is_tool("trivy"): trivy_exists = True

    if not trivy_exists and os.path.exists("/usr/local/bin/trivy"): 
        trivy_exists = True

    if not trivy_exists:
        msg = "ERROR: Could not retrieve trivy to scan the image"
        results = {"status":False}
        results["log"] = msg
        return results

    os.environ["TIMEOUT"] = "1800"

    repository_uri = os.environ["REPOSITORY_URI"]
    tag = os.environ["COMMIT_HASH"][0:6]
    fqn_image = "{}:{}".format(repository_uri,tag)

    cmds = [ "trivy {}".format(fqn_image) ]

    try:
        results = run_cmds(cmds)
    except:
        results = {"status":False}
        results["log"] = "TIMED OUT scanning {}".format(fqn_image)

    return results

def push_image():

    """
    wrapper around shellout to push docker image

    Returns
    -------
    results - dict
        results of the pushing the image to repository
    """

    repository_uri = os.environ["REPOSITORY_URI"]
    ecr_login = os.environ["ECR_LOGIN"]
    tag = os.environ["COMMIT_HASH"][0:6]
    print("Pushing image to repository {}, tag = {}".format(repository_uri,tag))
    cmds = []
    cmds.append(ecr_login)
    cmd = "docker push {}:{}".format(repository_uri,tag)
    cmds.append(cmd)

    os.environ["TIMEOUT"] = "300"

    try:
        results = run_cmds(cmds)
    except:
        results = {"status":False}
        results["log"] = "TIMED OUT pushing image to registry"

    return results

class LocalDockerCI(object):

    """
    A helper class that looks a file location
    to perform docker builds according to a 
    build yaml file.
    ...
    Attributes
    ----------
    Methods
    -------
    clear_queue()
        clears the build queue that is a location on the filesystem.
    _get_next_build()
        gets the next build to work on for the process
    _load_webhook(file_path)
        loads the webhook information in the yaml file
    _clone_code(loaded_yaml)
        clones the repository according the commit hash in the yaml file
    _test_code()
        test the code if specified
    _build_image()
        a class entry point for building the Docker image
    _push_image()
        a class entry point for pushing the Docker image
    _run()
        an class method for running a single CI run
    run(loaded_yaml)
        the main class method for running a single CI run
        it is a while loop that keeps on checking the build queue
    """

    def __init__(self):

        """
        Environment Variable
        -------
        FASTEST_CI_QUEUE_DIR - str
            the file location for the filesystem queue
        """
  
        self.build_queue_dir = os.environ.get("FASTEST_CI_QUEUE_DIR",
                                              "/var/tmp/docker/fastest-ci/queue")

    def clear_queue(self):

        """
        clears the build queue that is a location on the filesystem.

        Return
        -------
            the output from the system shellout
        """

        print("clearing queue {} on init".format(self.build_queue_dir))
        return os.system("rm -rf {}/*".format(self.build_queue_dir))

    def _get_next_build(self):

        """
        gets the next build yaml

        Return
        -------
        filename - str
            the file yaml config for the next build
        """

        filenames = sorted(os.listdir(self.build_queue_dir))
        if not filenames: return

        print('Queue contains {}'.format(filenames))

        filename = os.path.join(self.build_queue_dir,filenames[0])

        print('Returning {} to build'.format(filename))

        return filename

    def _load_webhook(self,file_path):

        """
        loads webhook payload from yaml

        Returns
        -------
        results - dict
            the miscellaneous metadata from loading the build yaml
        loaded_yaml - dict
            the values of the build yaml
        """

        results = {"start_time":str(int(time()))}
        results["human_description"] = "loading webhook information"
        results["role"] = "github/webhook_read"
        results["status"] = "in_progress"

        try:
            yaml_str = open(file_path,'r').read()
            loaded_yaml = dict(yaml.safe_load(yaml_str))
            msg = "payload from github webhook loaded and read successfully"
            print(msg)
            results["status"] = "completed"
        except:
            loaded_yaml = None
            msg = "ERROR: could not load yaml at {} - skipping build".format(file_path)
            print("-"*32)
            print(msg)
            print("-"*32)
            results["status"] = "failed"

        if not results.get("log"): results["log"] = msg
        print(results.get("log"))

        os.system("rm -rf {}".format(file_path))

        return results,loaded_yaml

    def _clone_code(self,loaded_yaml):

        """
        clone code from git repository with the correct commit hash

        Parameters
        -------
        loaded_yaml - dict
            the loaded yaml is the input for cloning the repository

        Return
        -------
        results - dict
            the miscellaneous metadata from cloning code process
        """

        event_type = loaded_yaml.get("event_type")
        src_branch = loaded_yaml.get("src_branch")
        branch = loaded_yaml.get("branch")
        if not branch: branch = "master"

        os.environ["REPO_KEY_LOC"] = os.environ.get("REPO_KEY_LOC","/var/tmp/docker/files/autogenerated/deploy.pem")
        os.environ["DOCKER_BUILD_DIR"] = os.environ.get("DOCKER_BUILD_DIR","/var/tmp/docker/build")
        os.environ["REPO_URL"] = loaded_yaml["repo_url"]
        os.environ["COMMIT_HASH"] = loaded_yaml["commit_hash"]

        # if push, then we should use branch
        os.environ["REPO_BRANCH"] = branch

        # if pull request, then we should use src branch that 
        # is being pulled in
        if event_type == "pull_request" and src_branch:
            os.environ["REPO_BRANCH"] = src_branch

        results = {"start_time":str(int(time()))}
        results["human_description"] = "git pull of {} commit {}".format(loaded_yaml["repo_url"],loaded_yaml["commit_hash"])
        results["role"] = "git/clone_code"
        results["status"] = "in_progress"

        _cresults = git_clone_repo()

        if _cresults.get("log"): 
            results["log"] = _cresults["log"]

        if _cresults.get("status") is False: 
            msg = "ERROR: cloning code failed"
            results["status"] = "failed"
        else:
            msg = "cloning code succeeded"
            results["status"] = "completed"

        if not results.get("log"): results["log"] = msg
        print(results.get("log"))

        return results

    def _test_code(self):

        """optional executes code test through Docker

        Return
        -------
        results - dict
            the miscellaneous metadata from testing the code
        """

        results = {"start_time":str(int(time()))}
        results["human_description"] = "test of coding with {}".format(os.environ["DOCKER_FILE_TEST"])
        results["role"] = "docker/unit_test"
        results["status"] = "in_progress"
        # REPOSITORY_URI This needs to be set for builds
        _tresults = build_image(os.environ["DOCKER_FILE_TEST"])
        if _tresults.get("log"): results["log"] = _tresults["log"]

        if _tresults.get("status") is False: 
            msg = "ERROR: testing of code failed"
            results["status"] = "failed"
        else:
            msg = "testing of code succeeded"
            results["status"] = "completed"

        if not results.get("log"): results["log"] = msg
        print(results.get("log"))

        return results

    def _build_image(self):

        """builds the docker image

        Return
        -------
        results - dict
            the miscellaneous metadata from building image
        """

        results = {"start_time":str(int(time()))}
        results["human_description"] = "building of image with {}".format(os.environ["DOCKER_FILE"])
        results["role"] = "docker/build"
        results["status"] = "in_progress"

        # REPOSITORY_URI This needs to be set for builds
        dockerfile = os.environ.get("DOCKER_FILE")
        if not dockerfile: dockerfile = "Dockerfile"
        _bresults = build_image(dockerfile)
        if _bresults.get("log"): results["log"] = _bresults["log"]

        if not _bresults.get("status"):
            results["status"] = "failed"
            msg = "building of image failed"
        else:
            results["status"] = "completed"
            msg = "building of image succeeded"

        if not results.get("log"): results["log"] = msg
        print(results.get("log"))

        return results

    def _push_image(self):

        """pushs the docker image to the repo

        Return
        -------
        results - dict
            the miscellaneous metadata from pushing the image
        """

        results = {"start_time":str(int(time()))}
        results["human_description"] = "pushing of image"
        results["role"] = "docker/push"
        results["status"] = "in_progress"

        _presults = push_image()
        if _presults.get("log"): results["log"] = _presults["log"]

        if not _presults.get("status"):
            msg = "pushing of image failed"
            results["status"] = "failed"
        else:
            msg = "pushing of image succeeded"
            results["status"] = "completed"

        if not results.get("log"): results["log"] = msg
        print(results.get("log"))

        return results

    def _scan_image(self):

        """scans the container image

        Return
        -------
        results - dict
            the miscellaneous metadata from scanning the image
        """

        results = {"start_time":str(int(time()))}
        results["human_description"] = "scanning of image"
        results["role"] = "security/scan"
        results["status"] = "in_progress"

        _sresults = scan_image()
        if _sresults.get("log"): results["log"] = _sresults["log"]

        if not _sresults.get("status"):
            msg = "scanning of image failed"
            results["status"] = "failed"
        else:
            msg = "scanning of image succeeded"
            results["status"] = "completed"

        if not results.get("log"): results["log"] = msg
        print(results.get("log"))

        return results

    def _run(self):

        """internal run entry point to process one build config

        Return
        -------
        status - choice
           successful - if the build run is successful
           failed - if the build run is failed
        loaded_yaml - dict
           the values of the build yaml
        """

        file_path = self._get_next_build()
        if not file_path: return None,None,None

        # load webhook
        wresults,loaded_yaml = self._load_webhook(file_path)
        if wresults.get("status") == "failed": return wresults["status"],loaded_yaml

        # clone code
        cresults = self._clone_code(loaded_yaml)
        if cresults.get("status") == "failed": return cresults.get("status"),loaded_yaml

        # test code if necessary
        if os.environ.get("DOCKER_FILE_TEST") and os.path.exists("{}/{}".format(os.environ["DOCKER_BUILD_DIR"],os.environ["DOCKER_FILE_TEST"])):
            print('executing Docker test with {}'.format(os.environ["DOCKER_FILE_TEST"]))
            tresults = self._test_code()
            if tresults.get("status") == "failed": return tresults.get("status"),loaded_yaml

        # build code
        bresults = self._build_image()
        if bresults.get("status") == "failed": return bresults.get("status"),loaded_yaml

        # push image
        presults = self._push_image()
        if presults.get("status") == "failed": return presults.get("status"),loaded_yaml

        # scan image
        enable_scan_file = "{}/{}/{}".format(os.environ["DOCKER_BUILD_DIR"],"elasticdev","security_scan")
        if os.path.exists(enable_scan_file):
            sresults = self._scan_image()
            if sresults.get("status") == "failed": return sresults.get("status"),loaded_yaml

        return "successful",loaded_yaml

    def run(self):

        """main entry point as a daemon to periodically check the filesystem build queue
        """

        while True:

            status,loaded_yaml = self._run()

            if status:
                print("The webhook info has been loaded and processed. \n{}".format(loaded_yaml))

            sleep(1)

if __name__ == "__main__":

    main = LocalDockerCI()
    main.clear_queue()
    main.run()
