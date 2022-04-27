#!/usr/bin/python

import os
import yaml
import json
import requests
import ipaddress
from hashlib import sha1
from sys import hexversion
from time import time

import hmac
import six

from flask import request
from flask import Flask

from flask_restful import Resource
from flask_restful import Api

app = Flask(__name__)
api = Api(app)

class WebhookProcess(object):

    """
    A class that processing the webhooks 
    from Github and Bitbuckets, and passes the
    information to the ci service through a 
    simple queue in the form of a filesystem.
    ...
    Attributes
    ----------
    Methods
    -------
    _check_secret()
       returns True if webhook secret is correct
    _get_github_hook_blocks()
       returns a block of valid ipaddresses used by Github
    _get_bitbucket_hook_blocks()
       returns a block of valid ipaddresses used by Bitbucket
    _get_hook_blocks_by_headers()
       returns a block of valid ipaddresses used by the code repo
    _check_src_ip()
       returns True if webhook source ipaddress is valid
    _get_payload_fields()
       returns the payload fields from the webhook
    _get_bitbucket_payload()
       returns the payload fields from a Bitbucket webhook
    _get_github_payload()
       returns the payload fields from a Github webhook
    _check_trigger_id(trigger_id)
       returns True if trigger id is correct from the http post
    _check_trigger_branch(branch)
       returns True if the code branch is one of the listed to build on
    post()
         receives a webhook, checks whether to on build on it,
         creates the build yaml, and writes the file queue
    """

    def __init__(self):

        '''
        the webhook events we build on:
           push
           pull_request
        '''
  
        self.events = [ "push", "pull_request" ]

    def _check_secret(self):

        """Checks the Webhook secret in the post is correct

        Returns
        -------
        True
            if the secret is correct
        None
            no secret is provided in the call
        msg 
            a failed "msg" if check faiils
        """
  
        header_signature = request.headers.get('X-Hub-Signature')

        if not header_signature:
            print("WARN: header_signature not provided - no secret check")
            return
  
        if self.secret is not None and not isinstance(self.secret,six.binary_type):
            self.secret = self.secret.encode('utf-8')
  
        sha_name, signature = header_signature.split('=')
        if sha_name != 'sha1':
            msg = "sha_name needs to be sha1"
            return msg
  
        # HMAC requires the key to be bytes, but data is string
        mac = hmac.new(self.secret, msg=request.data, digestmod=sha1)
  
        # Python prior to 2.7.7 does not have hmac.compare_digest
        if hexversion >= 0x020707F0:
            if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                msg = "Digest does not match signature"
                return msg
        else:
            if not str(mac.hexdigest()) == str(signature):
                msg = "Digest does not match signature"
                return msg
  
        return True

    def _get_github_hook_blocks(self):

        """Gets the list of hook ipaddresss for Github as the source

        Returns
        -------
        status - boolean
            False - if the check fails
            True  - if the check succeeds
        results - list
            the hook blocks for the ipaddresses on Github
        """

        try:
            results = requests.get('https://api.github.com/meta').json()["hooks"]
            status = True
        except:
            status = False
            msg_prefix = "Data is missing to check the acceptable ipaddresses"
            results = "{}\n{}".format(msg_prefix,requests.get('https://api.github.com/meta').json())
            print(results)

        return status,results

    def _get_bitbucket_hook_blocks(self):

        """Gets the list of hook ipaddresss for Bitbucket as the source

        Returns
        -------
        status - boolean
            False - if the check fails
            True  - if the check succeeds
        results - list
            the hook blocks for the ipaddresses on Bitbucket
        """

        try:
            results = [ entry["cidr"] for entry in requests.get('https://ip-ranges.atlassian.com').json()["items"] ]
            status = True
        except:
            status = False
            msg_prefix = "Data is missing to check the acceptable ipaddresses"
            results = "{}\n{}".format(msg_prefix,requests.get('https://ip-ranges.atlassian.com').json())
            print(results)

        return status,results

    def _get_hook_blocks_by_headers(self):

        """Gets the list of hook ipaddresss the code repository

        Returns
        -------
        status - boolean
            False - if the check fails
            True  - if the check succeeds
        results - list
            the hook blocks for the ipaddresses on Bitbucket
        provider - str
            bitbucket or github
        """

        user_agent = str(request.headers.get('User-Agent')).lower()

        if "bitbucket" in user_agent: 
            status,results = self._get_bitbucket_hook_blocks()
            provider = "bitbucket"
        else:
            status,results = self._get_github_hook_blocks()
            provider = "github"

        return provider,status,results

    def _check_src_ip(self):

        """Checks the source ip of the webhook

        Returns
        -------
        True
            if the source ip is acceptable
        msg 
            the failed message
        """

        # Check if the POST request is from github.com/bitbucket
        if os.environ.get('GHE_ADDRESS'):
            hook_blocks = [str(os.environ.get('GHE_ADDRESS'))]
        else:
            provider,status,hook_blocks = self._get_hook_blocks_by_headers()
            if status is False: return 'could not determine src ip acceptable "{}" ipaddresses'.format(provider)

        if len(request.access_route) > 1:
            remote_ip = request.access_route[-1]
        else:
            remote_ip = request.access_route[0]

        request_ip = ipaddress.ip_address('{0}'.format(remote_ip))

        for block in hook_blocks:
            if ipaddress.ip_address(request_ip) in ipaddress.ip_network(block):
                print('request_ip = {} is in the list of acceptable "{}" ipaddresses'.format(request_ip,provider))
                return True

        msg = "{} is not in list of accepted src ipaddresses".format(request_ip)

        return msg

    def _get_payload_fields(self):

        """Fetches and transforms the webhook payload

        Returns
        -------
        payload - dict
            the normalized payload for the code repository's webhook
        """

        # Get bitbucket fields
        # User-Agent: Bitbucket-Webhooks/2.0
        user_agent = str(request.headers.get('User-Agent')).lower()
        if "bitbucket" in user_agent:
            return self._get_bitbucket_payload()

        # Get github fields
        event_type = request.headers.get('X-GitHub-Event')
        if event_type: return self._get_github_payload()

    def _get_bitbucket_payload(self):

        """Fetches and transforms the webhook payload for Bitbucket

        Returns
        -------
        payload - dict
            the normalized payload for bitbucket webhook
        """

        # X-Event-Key: repo:push
        event_type = str(request.headers.get('X-Event-Key'))
        payload = json.loads(request.data)

        results = {}

        if event_type == "repo:push": 

            # Make it more like github, just call it push
            event_type = "push"

            commit_info = payload["push"]["changes"][0]["commits"][0]

            commit_hash = commit_info["hash"]
            results["message"] = commit_info["message"]

            if commit_info.get("user"):
                results["author"] = commit_info["author"]["user"]["display_name"]
            else:
                results["author"] = commit_info["author"]["raw"]

            results["authored_date"] = commit_info["date"]
            # add these fields to make it consistent with Github
            results["committer"] = results["author"]
            results["committed_date"] = results["authored_date"]

            results["url"] = commit_info["links"]["html"]["href"]
            results["repo_url"] = payload["repository"]["links"]["html"]["href"]

            # More fields
            results["compare"] = payload["push"]["changes"][0]["links"]["html"]["href"]

            try:
                results["email"] = commit_info["author"]["raw"].split("<")[1].split(">")[0].strip()
            except:
                results["email"] = commit_info["author"]["raw"]

            results["branch"] = payload["push"]["changes"][0]["new"]["name"]

        #if event_type in ["pullrequest:created","pullrequest:updated"]:
        if event_type in ["pullrequest:created"]:

            # Make it more like github, just call it push
            event_type = "pull_request"

            pullrequest = payload["pullrequest"]
            source_hash = pullrequest["source"]["commit"]["hash"]
            dest_hash = pullrequest["destination"]["commit"]["hash"]

            # Branch to commit pull request to
            dest_branch = pullrequest["destination"]["branch"]["name"]
            src_branch = pullrequest["source"]["branch"]["name"]
  
            results["dest_branch"] = dest_branch
            results["src_branch"] = src_branch
            results["branch"] = dest_branch

            commit_hash = source_hash
            results["message"] = pullrequest["title"]
            results["author"] = pullrequest["author"]["display_name"]
            results["url"] = pullrequest["source"]["commit"]["links"]["html"]["href"]
            results["created_at"] = pullrequest["created_on"]
            results["authored_date"] = pullrequest["created_on"]
            results["updated_at"] = pullrequest["updated_on"]
            results["committer"] = None
            results["committed_date"] = None
            results["repo_url"] = pullrequest["destination"]["repository"]["links"]["html"]["href"]
            #https://bitbucket.org/williaumwu/flask_sample/branches/compare/53cb2d5270c6..917c834ee6a6
            results["compare"] = "{}/branches/compare/{}..{}".format(results["repo_url"],source_hash,dest_hash)
            #results["email"] = None

        results["event_type"] = event_type

        if event_type == "pull_request" or event_type == "push":
            results["commit_hash"] = commit_hash
            return results

        # we will provide a message if failed
        failed_msg = "event_type = {} not allowed".format(event_type)
        results = {"status":False}
        results["failed_msg"] = failed_msg

    def _get_github_payload(self):

        """Fetches and transforms the webhook payload for Github

        Returns
        -------
        payload - dict
            the normalized payload for github webhook
        """

        payload = json.loads(request.data)
        event_type = request.headers.get('X-GitHub-Event')

        results = {}

        if event_type == "push": 
            commit_hash = payload["head_commit"]["id"]
            results["message"] = payload["head_commit"]["message"]
            results["author"] = payload["head_commit"]["author"]["name"]
            results["authored_date"] = payload["head_commit"]["timestamp"]
            results["committer"] = payload["head_commit"]["committer"]["name"]
            results["committed_date"] = payload["head_commit"]["timestamp"]
            results["url"] = payload["head_commit"]["url"]
            results["repo_url"] = payload["repository"]["html_url"]
            
            # More fields
            results["compare"] = payload["compare"]
            results["email"] = payload["head_commit"]["author"]["email"]

            results["branch"] = payload["ref"].split("refs/heads/")[1]

        if event_type == "pull_request": 
            commit_hash = payload["pull_request"]["head"]["sha"]
            results["message"] = payload["pull_request"]["body"]
            results["author"] = payload["pull_request"]["user"]["login"]
            results["url"] = payload["pull_request"]["user"]["url"]
            results["created_at"] = payload["pull_request"]["created_at"]
            results["authored_date"] = payload["pull_request"]["created_at"]
            results["committer"] = None
            results["committed_date"] = None
            results["updated_at"] = payload["pull_request"]["updated_at"]

            dest_branch = payload["pull_request"]["base"]["ref"]
            src_branch = payload["pull_request"]["head"]["ref"]

            results["dest_branch"] = dest_branch
            results["src_branch"] = src_branch
            results["branch"] = dest_branch

        results["event_type"] = event_type

        if event_type == "pull_request" or event_type == "push":
            results["commit_hash"] = commit_hash
            return results

        failed_msg = "event_type = {} not allowed".format(event_type)
        results = {"status":False}
        results["failed_msg"] = failed_msg

        return results

    def _check_trigger_id(self,trigger_id):

        """checks the trigger id in the webhook post

        Parameters
        -------
        trigger_id - str
            trigger id from the webhook post

        Returns
        -------
        True
            if trigger_id is valid
        msg 
            a failed "msg" if check faiils
        """

        if str(trigger_id) != self.trigger_id:
            return "trigger id {} doesn't match expected {}".format(str(trigger_id),self.trigger_id)

        return True

    def _check_trigger_branch(self,branch):

        """checks the trigger branch in the webhook post

        Parameters
        -------
        branch - branch from the webhook post

        Returns
        -------
        True
            if branch is valid
        msg 
            a failed "msg" if check faiils
        """

        if str(branch) == str(self.trigger_branch): return True

        failed_msg = "Trigger branch {} does not match branch {} to test and build on".format(str(branch),self.trigger_branch)
        return failed_msg

    def post(self,**kwargs):

        """
        receives a webhook, checks whether to on build on it,
        creates the build yaml, and writes the file queue

        Parameters
        -------
        kwargs - k,v of the webhook payload

        Returns
        -------
        None
            if the webhook was processed
        Results - dict
            a dictionary with the failed or problem with the webhook processing

        """

        # Check ipaddress
        _msg_status = self._check_src_ip()

        if _msg_status is not True: 
            print(_msg_status)
            return {"msg":_msg_status}

        print("source ip checked out ok")

        _msg_status = self._check_trigger_id(kwargs["trigger_id"])

        if _msg_status is not True: 
            print(_msg_status)
            return {"msg":_msg_status}

        print("trigger_id checked out ok")

        _msg_status = self._check_secret()

        if _msg_status is True: 
            print("secret checked out ok")
        elif _msg_status and _msg_status is not True: 
            print(_msg_status)
            return {"msg":_msg_status}

        payload = self._get_payload_fields()

        if payload.get("failed_msg"): 
            print(payload["failed_msg"])
            return {"msg":payload["failed_msg"]}

        print("payload checked out ok")
     
        _msg_status = self._check_trigger_branch(payload["branch"])

        if _msg_status is not True: 
            print(_msg_status)
            return {"msg":_msg_status}

        if _msg_status is not True: 
            print(_msg_status)
            return {"msg":_msg_status}

        print("trigger branch checked out ok")

        filepath = os.path.join(self.build_queue_dir,str(int(time())))

        with open(filepath, 'w') as yaml_file:
            yaml_file.write(yaml.safe_dump(payload,default_flow_style=False))

        # writes the yaml build file that will be 
        # picked up by the build microservice
        print("file written here {}".format(filepath))

class FastestDockerCI(WebhookProcess,Resource):

    '''
    the main entrypoint class for the Flask API
    '''

    def __init__(self):
  
        self.events = [ "push", "pull_request" ]
        self.build_queue_dir = os.environ.get("FASTEST_CI_QUEUE_DIR","/var/tmp/docker/fastest-ci/queue")
        self.trigger_id = str(os.environ["TRIGGER_ID"])
        self.trigger_branch = str(os.environ["TRIGGER_BRANCH"])

        self.secret = os.environ.get("TRIGGER_SECRET")
        if self.secret: self.secret = str(self.secret)

        WebhookProcess.__init__(self)

api.add_resource(FastestDockerCI, '/<string:trigger_id>')

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8021,debug=True)
