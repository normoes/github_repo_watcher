"""

github_repo_watcher

author: Norman Moeschter-Schenck
email: norman.moeschter@gmail.com

Keep track of
* releases
* tags
* new commits to a branch (default=master)
for specific github repositories.

Results are stored in a database.

In case a webhook is defined, it is triggered.
This can be used to trigger build pipelines when a new tag/version was released.
This can also be used to trigger Mattermost webhooks to automatically post to channels.
"""


import logging
import os

import requests

from utils import database
from utils.exceptions import ApiRateLimitExceededException, NotFoundException

from eventhooks import (
    MattermostWebHook,
    DockerCloudWebHook,
    AwsSesEmailHook,
    SimpleEmailHook,
)


logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
logging.getLogger("Event").setLevel(logging.INFO)

DEBUG = False

GITHUB = "github"
GITHUB_TAG_REALM = f"{GITHUB}_tags"
GITHUB_RELEASE_REALM = f"{GITHUB}_releases"
GITHUB_COMMIT_REALM = f"{GITHUB}_commits"
GITHUB_REALMS = {
    GITHUB_TAG_REALM: GITHUB_TAG_REALM,
    GITHUB_RELEASE_REALM: GITHUB_RELEASE_REALM,
    GITHUB_COMMIT_REALM: GITHUB_COMMIT_REALM,
}

# read securely stored environment variables set in AWS Lambda
# Use different variables locally
if "SERVERTYPE" in os.environ and os.environ["SERVERTYPE"] == "AWS Lambda":
    import boto3
    from botocore.exceptions import ClientError
    from base64 import b64decode

    session = boto3.session.Session()
    kms_client = session.client("kms")
    ssm_client = session.client("ssm")

    try:
        parameter = ssm_client.get_parameter(
            Name="/ses/smtp_credential_community", WithDecryption=True
        )
        AWS_SES_CREDENTIALS = parameter["Parameter"]["Value"]
    except ClientError as e:
        log.warning(e.response["Error"]["Code"])
        AWS_SES_CREDENTIALS = ""

    try:
        parameter = ssm_client.get_parameter(
            Name="/community.xmrto-dev/github_watcher_sender",
            WithDecryption=True,
        )
        AWS_SES_SENDER = parameter["Parameter"]["Value"]
    except ClientError as e:
        log.warning(e.response["Error"]["Code"])
        AWS_SES_SENDER = ""

    try:
        parameter = ssm_client.get_parameter(
            Name="/community.xmrto-dev/github_watcher_recipients",
            WithDecryption=True,
        )
        AWS_SES_RECIPIENTS = parameter["Parameter"]["Value"]
    except ClientError as e:
        log.warning(e.response["Error"]["Code"])
        AWS_SES_RECIPIENTS = ""

    try:
        parameter = ssm_client.get_parameter(
            Name="/community.xmrto-dev/github_watcher_recipients_infra",
            WithDecryption=True,
        )
        AWS_SES_RECIPIENTS_INFRA = parameter["Parameter"]["Value"]
    except ClientError as e:
        log.warning(e.response["Error"]["Code"])
        AWS_SES_RECIPIENTS_INFRA = ""

    try:
        parameter = ssm_client.get_parameter(
            Name="/community.xmrto-dev/github_watcher_recipients_sec",
            WithDecryption=True,
        )
        AWS_SES_RECIPIENTS_SEC = parameter["Parameter"]["Value"]
    except ClientError as e:
        log.warning(e.response["Error"]["Code"])
        AWS_SES_RECIPIENTS_SEC = ""
    try:
        parameter = ssm_client.get_parameter(
            Name="/community.xmrto-dev/github_watcher_recipients_dom",
            WithDecryption=True,
        )
        AWS_SES_RECIPIENTS_DOM = parameter["Parameter"]["Value"]
    except ClientError as e:
        log.warning(e.response["Error"]["Code"])
        AWS_SES_RECIPIENTS_DOM = ""

    try:
        parameter = ssm_client.get_parameter(
            Name="/community.xmrto-dev/github_watcher_recipients_g",
            WithDecryption=True,
        )
        AWS_SES_RECIPIENTS_G = parameter["Parameter"]["Value"]
    except ClientError as e:
        log.warning(e.response["Error"]["Code"])
        AWS_SES_RECIPIENTS_G = ""

    ENCRYPTED = os.environ["DATABASE_URL"]
    # Decrypt code should run once and variables stored outside of the function
    # handler so that these are decrypted once per container
    DATABASE_URL = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["MATTERMOST_MONERO_URL"]
    MATTERMOST_MONERO_URL = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["MATTERMOST_MONERO_TOKEN"]
    MATTERMOST_MONERO_TOKEN = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["MATTERMOST_BITCOIN_URL"]
    MATTERMOST_BITCOIN_URL = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["MATTERMOST_BITCOIN_TOKEN"]
    MATTERMOST_BITCOIN_TOKEN = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_MONERO_SOURCE"]
    DOCKER_HUB_MONERO_SOURCE = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_MONERO_TOKEN"]
    DOCKER_HUB_MONERO_TOKEN = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_BITCOIN_SOURCE"]
    DOCKER_HUB_BITCOIN_SOURCE = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_BITCOIN_TOKEN"]
    DOCKER_HUB_BITCOIN_TOKEN = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_LIGHTNING_SOURCE"]
    DOCKER_HUB_LIGHTNING_SOURCE = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_LIGHTNING_TOKEN"]
    DOCKER_HUB_LIGHTNING_TOKEN = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_AEON_SOURCE"]
    DOCKER_HUB_AEON_SOURCE = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    ENCRYPTED = os.environ["DOCKER_HUB_AEON_TOKEN"]
    DOCKER_HUB_AEON_TOKEN = bytes.decode(
        kms_client.decrypt(CiphertextBlob=b64decode(ENCRYPTED))["Plaintext"]
    )
    DB_TYPE = database.POSTGRES
else:
    log.setLevel(logging.DEBUG)
    logging.getLogger("Event").setLevel(logging.DEBUG)
    # DB_TYPE = database.SQLITE
    # DATABASE_URL = "data.db"
    DB_TYPE = database.POSTGRES
    DATABASE_URL = "postgres@localhost:5432/test"
    # Add 'nosec' commentto make bandit ignore: [B105:hardcoded_password_string]
    MATTERMOST_MONERO_URL = ""  # nosec
    MATTERMOST_MONERO_TOKEN = ""  # nosec
    MATTERMOST_BITCOIN_URL = ""  # nosec
    MATTERMOST_BITCOIN_TOKEN = ""  # nosec
    DOCKER_HUB_MONERO_SOURCE = ""  # nosec
    DOCKER_HUB_MONERO_TOKEN = ""  # nosec
    DOCKER_HUB_BITCOIN_SOURCE = ""  # nosec
    DOCKER_HUB_BITCOIN_TOKEN = ""  # nosec
    DOCKER_HUB_LIGHTNING_SOURCE = ""  # nosec
    DOCKER_HUB_LIGHTNING_TOKEN = ""  # nosec
    DOCKER_HUB_AEON_SOURCE = ""  # nosec
    DOCKER_HUB_AEON_TOKEN = ""  # nosec
    AWS_SES_CREDENTIALS = ""  # nosec
    AWS_SES_SENDER = ""  # nosec
    AWS_SES_RECIPIENTS = ""  # nosec
    AWS_SES_RECIPIENTS_INFRA = ""  # nosec
    AWS_SES_RECIPIENTS_SEC = ""  # nosec
    AWS_SES_RECIPIENTS_DOM = ""  # nosec
    AWS_SES_RECIPIENTS_G = ""  # nosec


class Watcher:
    """Base class for
    """

    def __init__(self, db=None, events=None):
        self.db = db
        self.events = events

    def request_json(self, url):
        return self.request_url(url).json()

    def request_url(self, url):
        """Requests the given URL.

        :returns: JSON response, if JSON
        """
        log.debug(f"URL: '{url}'.")
        response = requests.get(url=url)

        status_code = response.status_code
        if status_code not in [200, 301, 302]:
            if status_code == 404:
                raise NotFoundException(f"Nothing found at '{url}'.")
            elif status_code == 403:
                raise ApiRateLimitExceededException(
                    f"API rate limit exceeded: Response: '{response.text}'."
                )
            else:
                raise ValueError(
                    f"Status code '{status_code}' with '{response.text}'."
                )
        return response

    def release_exists(self, release):
        """Allow update with unique release.

        No same 'tag_name' and 'release_name'.

        :param release: dictionary incl. 'tag_name' and 'release_name' of a release
        :returns: False or True, if release already exists
        """
        exists = self.db.release_exists(release)
        if exists:
            log.warning(f"Release already exists: '{release}'.")
        return exists

    def commit_exists(self, commit):
        """Allow update with unique commit.

        No same 'branch' and 'sha'.

        :param commit: dictionary incl. 'branch' and 'sha' of a commit
        :returns: False or True, if commit already exists
        """
        if not self.db:
            return False
        exists = self.db.commit_exists(commit)
        if exists:
            log.warning(f"Commit already exists: '{commit}'.")
        return exists

    def get_commit_hash(self, commit):
        """Get the value of 'sha' from the 'commit' key.
        """
        if not self.db:
            return False
        if not commit:
            raise ValueError("No commit found in response: '{commit}'.")
        commit_hash = commit.get(self.KEY_COMMIT_HASH, None)

        return commit_hash

    def tag_exists(self, tag):
        """Allow update with unique tag.

        No same 'tag_name' and 'sha'.

        :param commit: dictionary incl. 'tag_name' and 'sha' of a tag
        :param db: database
        :returns: False or True, if tag already exists
        """
        if not self.db:
            return False
        exists = self.db.tag_exists(tag)
        if exists:
            log.warning(f"Tag already exists: '{tag}'.")
        return exists

    def trigger(self, data=None, realm=None, debug=False):
        if not self.events:
            log.warning("No events found.")
            return
        for event in self.events:
            if event:
                original_subject = ""
                # Add repository name to email subject.
                try:
                    if isinstance(event, AwsSesEmailHook) or isinstance(
                        event, SimpleEmailHook
                    ):
                        log.info(self.repo)
                        log.info(event.email.subject)
                        original_subject = event.email.subject
                        event.email.subject = (
                            event.email.subject + f" - {self.repo}"
                        )
                        log.info(event.email.subject)
                except Exception as e:
                    log.error(
                        f"Could not change email subject to contain repo name '{self.repo}'. Error: {str(e)}."
                    )
                event.trigger(data=data, realm=realm, debug=debug)
                # Restore original email subject.
                try:
                    if isinstance(event, AwsSesEmailHook) or isinstance(
                        event, SimpleEmailHook
                    ):
                        log.info(event.email.subject)
                        event.email.subject = original_subject
                        log.info(event.email.subject)
                except Exception as e:
                    log.error(
                        f"Could not reset email subject to original '{original_subject}'. Error: {str(e)}."
                    )


class GithubWatcher(Watcher):

    URL = "https://api.github.com/repos/{repo}/{endpoint}"
    ENDPOINT_LATEST_RELEASE = "releases/latest"
    ENDPOINT_LATEST_COMMIT = "branches/{branch}"
    ENDPOINT_LATEST_TAG = "tags"
    KEY_RELEASE_TAG_NAME = "tag_name"
    KEY_RELEASE_NAME = "name"
    KEY_COMMIT_NAME = "commit"
    KEY_COMMIT_HASH = "sha"
    KEY_TAG_NAME = "name"

    def __init__(
        self, repo="github/training-kit", db=None, events=None, debug=False
    ):
        self.debug = debug
        self.repo = repo
        self.url = self.URL.format(repo=repo, endpoint="{endpoint}")
        super().__init__(db=db, events=events)

    def check_repo(self):
        result = {"repo": self.repo}
        # latest realease
        release = self.get_recent_repo(repo=self.repo)
        if release:
            if not self.release_exists(release=release):
                if self.db and not self.debug:
                    self.db.insert_(database.RELEASES, release)
                data = f"New release for {self.repo}: '{release}'."
                self.trigger(
                    data=data, realm=GITHUB_RELEASE_REALM, debug=self.debug
                )
                result.update({"release": release})
        # latest commit on given branch (default=master)
        commit = self.get_recent_commit_on_branch(
            repo=self.repo, branch="master"
        )
        if commit:
            if not self.commit_exists(commit=commit):
                if self.db and not self.debug:
                    self.db.insert_(database.COMMITS, commit)
                data = f"New commit to 'master' for '{self.repo}': '{commit}'."
                self.trigger(
                    data=data, realm=GITHUB_COMMIT_REALM, debug=self.debug
                )
                result.update({"commit": commit})
        # latest tag
        tag = self.get_recent_tag(repo=self.repo)
        if tag:
            if not self.tag_exists(tag=tag):
                if self.db and not self.debug:
                    self.db.insert_(database.TAGS, tag)
                data = f"New tag for '{self.repo}': '{tag}'."
                self.trigger(
                    data=data, realm=GITHUB_TAG_REALM, debug=self.debug
                )
                result.update({"tag": tag})

        return result

    def get_recent_repo(self, repo):
        """Get the most recent release.

        :param repo: github repository to check
        :returns: most recent release
        """
        endpoint = self.ENDPOINT_LATEST_RELEASE
        try:
            url = self.url.format(endpoint=endpoint)
            log.info(url)
            response = self.request_json(url=url)
            tag_name = response.get(self.KEY_RELEASE_TAG_NAME, None)
            release_name = response.get(self.KEY_RELEASE_NAME, None)
            release = {
                "repo": repo,
                "tag_name": tag_name,
                "release_name": release_name,
            }
            log.info(f"Latest release: '{release}'.")
            return release
        except (
            ValueError,
            NotFoundException,
            ApiRateLimitExceededException,
        ) as e:
            log.warning(e)

        return None

    def get_recent_commit_on_branch(self, repo, branch="master"):
        """Get the most recent commit on given branch.

        :param repo: github repository to check
        :param branch: branch to get most recent commit from
        :returns: most recent commit hash on given branch
        """
        endpoint = self.ENDPOINT_LATEST_COMMIT.format(branch=branch)
        try:
            response = self.request_json(self.url.format(endpoint=endpoint))
            commit_hash = self.get_commit_hash(
                response.get(self.KEY_COMMIT_NAME, None)
            )
            commit = {"repo": repo, "branch": branch, "sha": commit_hash}
            log.info(f"Most recent commit: '{commit}'.")
            return commit
        except (
            ValueError,
            NotFoundException,
            ApiRateLimitExceededException,
        ) as e:
            log.warning(e)

        return None

    def get_recent_tag(self, repo):
        """Get the most recent tag.

        :param repo: github repository to check
        :returns: most recent tagand the according commit hash
        """
        endpoint = self.ENDPOINT_LATEST_TAG
        try:
            response = self.request_json(self.url.format(endpoint=endpoint))
            tag_name = response[0].get(self.KEY_TAG_NAME, None)
            commit_hash = self.get_commit_hash(
                response[0].get(self.KEY_COMMIT_NAME, None)
            )
            tag = {"repo": repo, "tag_name": tag_name, "sha": commit_hash}
            log.info(f"Most recent tag: '{tag}'.")
            return tag
        except (
            ValueError,
            NotFoundException,
            ApiRateLimitExceededException,
        ) as e:
            log.warning(e)

        return None


def check_repos(event, context):
    db = database.Db(dbtype=DB_TYPE, dbname=DATABASE_URL)

    news = []

    # General AWS SES email hook to send mails via AWS SES.
    # Trigger allowed for updates on github tags only.
    simple_email_trigger_tags = SimpleEmailHook(
        name="new_repository_tag",
        host="email-smtp.eu-west-1.amazonaws.com",
        credentials=AWS_SES_CREDENTIALS,
        sender=AWS_SES_SENDER,
        sender_name="github-repo-watcher-simple",
        recipients=AWS_SES_RECIPIENTS,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    aws_ses_email_trigger_tags_infra = AwsSesEmailHook(
        name="new_repository_tag",
        sender=AWS_SES_SENDER,
        sender_name="github-repo-watcher",
        recipients=AWS_SES_RECIPIENTS_INFRA,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    aws_ses_email_trigger_tags_sec = AwsSesEmailHook(
        name="new_repository_tag",
        sender=AWS_SES_SENDER,
        sender_name="github-repo-watcher",
        recipients=AWS_SES_RECIPIENTS_SEC,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    aws_ses_email_trigger_tags_dom = AwsSesEmailHook(
        name="new_repository_tag",
        sender=AWS_SES_SENDER,
        sender_name="github-repo-watcher",
        recipients=AWS_SES_RECIPIENTS_DOM,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    aws_ses_email_trigger_tags_g = AwsSesEmailHook(
        name="new_repository_tag",
        sender=AWS_SES_SENDER,
        sender_name="github-repo-watcher",
        recipients=AWS_SES_RECIPIENTS_G,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )

    # Commits on master trigger build for 'latest' docker image tag.
    monero_dockercloud_trigger_commits = DockerCloudWebHook(
        name="monero_commits_dockercloud",
        source_branch="master",
        source=DOCKER_HUB_MONERO_SOURCE,
        token=DOCKER_HUB_MONERO_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_COMMIT_REALM],),
    )
    # Trigger allowed for updates on github tags only.
    monero_dockercloud_trigger_tags = DockerCloudWebHook(
        name="monero_tags_dockercloud",
        source_branch="most_recent_tag",
        source=DOCKER_HUB_MONERO_SOURCE,
        token=DOCKER_HUB_MONERO_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    monero_mattermost_trigger = MattermostWebHook(
        name="monero_tags_mattermost",
        host=MATTERMOST_MONERO_URL,
        token=MATTERMOST_MONERO_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    # Commits on master trigger build for 'latest' docker image tag.
    bitcoin_dockercloud_trigger_commits = DockerCloudWebHook(
        name="bitcoin_commits_dockercloud",
        source_branch="master",
        source=DOCKER_HUB_BITCOIN_SOURCE,
        token=DOCKER_HUB_BITCOIN_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_COMMIT_REALM],),
    )
    # Commits on master trigger build for 'specific tag' and 'most_recent_tag' docker image tags.
    bitcoin_dockercloud_trigger_tags = DockerCloudWebHook(
        name="bitcoin_tags_dockercloud",
        source_branch="most_recent_tag",
        source=DOCKER_HUB_BITCOIN_SOURCE,
        token=DOCKER_HUB_BITCOIN_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    bitcoin_mattermost_trigger = MattermostWebHook(
        name="bitcoin_tags_mattermost",
        host=MATTERMOST_BITCOIN_URL,
        token=MATTERMOST_BITCOIN_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    # Commits on master trigger build for 'latest' docker image tag.
    lightning_dockercloud_trigger_commits = DockerCloudWebHook(
        name="lightning_commits_dockercloud",
        source_branch="master",
        source=DOCKER_HUB_LIGHTNING_SOURCE,
        token=DOCKER_HUB_LIGHTNING_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_COMMIT_REALM],),
    )
    # Commits on master trigger build for 'specific tag' and 'most_recent_tag' docker image tags.
    lightning_dockercloud_trigger_tags = DockerCloudWebHook(
        name="lightning_tags_dockercloud",
        source_branch="most_recent_tag",
        source=DOCKER_HUB_LIGHTNING_SOURCE,
        token=DOCKER_HUB_LIGHTNING_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    # Commits on master trigger build for 'latest' docker image tag.
    aeon_dockercloud_trigger_commits = DockerCloudWebHook(
        name="aeon_commits_dockercloud",
        source_branch="master",
        source=DOCKER_HUB_AEON_SOURCE,
        token=DOCKER_HUB_AEON_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_COMMIT_REALM],),
    )
    # Commits on master trigger build for 'specific tag' and 'most_recent_tag' docker image tags.
    aeon_dockercloud_trigger_tags = DockerCloudWebHook(
        name="aeon_tags_dockercloud",
        source_branch="most_recent_tag",
        source=DOCKER_HUB_AEON_SOURCE,
        token=DOCKER_HUB_AEON_TOKEN,
        realms=(GITHUB_REALMS[GITHUB_TAG_REALM],),
    )
    repos = (
        (
            "monero-project/monero",
            (
                monero_mattermost_trigger,
                monero_dockercloud_trigger_commits,
                monero_dockercloud_trigger_tags,
                simple_email_trigger_tags,
                aws_ses_email_trigger_tags_sec,
                aws_ses_email_trigger_tags_dom,
                aws_ses_email_trigger_tags_g,
            ),
        ),
        (
            "aeonix/aeon",
            (
                aeon_dockercloud_trigger_commits,
                aeon_dockercloud_trigger_tags,
                simple_email_trigger_tags,
                aws_ses_email_trigger_tags_dom,
            ),
        ),
        (
            "bitcoin/bitcoin",
            (
                bitcoin_dockercloud_trigger_commits,
                bitcoin_dockercloud_trigger_tags,
                bitcoin_mattermost_trigger,
                simple_email_trigger_tags,
                aws_ses_email_trigger_tags_sec,
                aws_ses_email_trigger_tags_g,
            ),
        ),
        (
            "lightningnetwork/lnd",
            (
                lightning_dockercloud_trigger_commits,
                lightning_dockercloud_trigger_tags,
                simple_email_trigger_tags,
                aws_ses_email_trigger_tags_sec,
                aws_ses_email_trigger_tags_g,
            ),
        ),
        (
            "python/black",
            (simple_email_trigger_tags, aws_ses_email_trigger_tags_dom),
        ),
        (
            "antonbabenko/pre-commit-terraform",
            (simple_email_trigger_tags, aws_ses_email_trigger_tags_infra),
        ),
        ("pre-commit/pre-commit-hooks", (simple_email_trigger_tags,),),
        (
            "serverless/serverless",
            (
                simple_email_trigger_tags,
                aws_ses_email_trigger_tags_infra,
                aws_ses_email_trigger_tags_g,
            ),
        ),
        (
            "terraform-linters/tflint",
            (simple_email_trigger_tags, aws_ses_email_trigger_tags_infra),
        ),
        (
            "hashicorp/terraform",
            (
                simple_email_trigger_tags,
                aws_ses_email_trigger_tags_infra,
                aws_ses_email_trigger_tags_sec,
                aws_ses_email_trigger_tags_g,
            ),
        ),
    )
    for repo, events in repos:
        log.info(f"Checking: '{repo}'.")
        watcher = GithubWatcher(repo=repo, db=db, events=events, debug=DEBUG)
        news.append(watcher.check_repo())

    log.info(news)

    return news


if __name__ == "__main__":
    news = check_repos(event=None, context=None)
    for i, new in enumerate(news):
        if "repo" in new:
            print(f"{i}" + ": " + new.pop("repo"))
        if len(new) > 0:
            for key, value in new.items():
                print(f" {key}: {value}")
        else:
            print("  No news.")
