import requests
import logging
from utils import database
from utils.exceptions import ApiRateLimitExceededException, NotFoundException

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)

# REALEASES
# curl --silent "https://api.github.com/repos/monero-project/monero/releases/latest" | grep '"tag_name":' | cut -d ':' -f2 | tr -d '", '
# curl --silent "https://api.github.com/repos/monero-project/monero/releases" | grep '"tag_name":' | cut -d ':' -f2 | tr -d '", ' | head -n1
#URL = "https://api.github.com/repos/{0}/{1}"

# TAGS

# BRANCHES (LAST COMMIT)
# curl https://api.github.com/repos/monero-project/monero/branches/master
# {
#  "name": "master",
#  "commit": {
#    "sha": "77e1ebff26aeb1466a79f2535b66f165c62468ab", <-- last commit


class WatchEvent():
    def __init__(self, webhook=""):
        pass


class WebHook(WatchEvent):
    def __init__(self, name="", url=""):
        self.name = name
        self.url = url
        log.info("Webhook event URL {}".format(self.url))
        super().__init__()

    def _trigger(self, url="", branch=""):
        log.info("branch {} triggered: {}".format(branch, str(self)))
        print(self)
        data = {"source_type": "Branch", "source_name": branch}
        response = requests.post(self.url, json=data)
        if not response:
            log.warn("no response")
            return None
        log.debug(response.json())
        return response

    def __str__(self):
        return self.name + " at " + self.url
        


class DockerCloudWebHook(WebHook):
    URL = "https://cloud.docker.com/api/build/v1/source/{trigger_url}"

    def __init__(self,name="",  trigger_url=""):
        super().__init__(name=name, url=self.URL.format(trigger_url=trigger_url))

    def trigger(self, branch):
        if not branch:
            # trigger all builds
            return None
        # trigger specific branch
        # return self._trigger(url=self.url, branch=branch)


class Watcher():
    def __init__(self, db=None, webhook=None):
        self.db = db
        self.webhook = webhook

    def request_json(self, url):
         return self.request_url(url).json()

    def request_url(self, url):
        """Requests the given URL.

        :returns: JSON response
        """
        log.debug('URL: {url}'.format(url=url))
        response = requests.get(url=url)

        status_code = response.status_code
        if status_code not in [200, 301, 302]:
            if status_code == 404:
                raise NotFoundException('nothing found at {}'.format(url))
            elif status_code == 403:
                raise ApiRateLimitExceededException('API rate limit exceeded.')
            else:
                raise ValueError('status code {} with {}'.format(status_code,
                                                                 response.text))
        # log.debug('response: {}'.format(response.json()))
        return response

    def release_exists(self, release):
        """Allow update with unique release.

        No same 'tag_name' and 'release_name'.

        :param release: dictionary incl. 'tag_name' and 'release_name' of a release
        :returns: False or True, if release already exists
        """
        exists = self.db.release_exists(release)
        if exists:
            log.warn('Release already exists: {}'.format(release))
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
            log.warn('Commit already exists: {}'.format(commit))
        return exists

    def get_commit_hash(self, commit):
        """Get the value of 'sha' from the 'commit' key.
        """
        if not self.db:
            return False
        if not commit:
            raise ValueError("No commit found in response: {}".format(commit))
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
            log.warn('Tag already exists: {}'.format(tag))
        return exists

    def trigger(self, branch=""):
        if not self.webhook:
            log.warn("No webhook found.")
            return False
        return self.webhook.trigger(branch=branch)
        


class GithubWatcher(Watcher):

    URL = "https://api.github.com/repos/{repo}/{endpoint}"
    ENDPOINT_LATEST_RELEASE = "releases/latest"
    ENDPOINT_LATEST_COMMIT = "branches/{branch}"
    ENDPOINT_LATEST_TAG = "tags"
    KEY_TAG_NAME = "tag_name"
    KEY_RELEASE_NAME = "name"
    KEY_COMMIT_NAME = "commit"
    KEY_COMMIT_HASH = "sha"
    KEY_TAG_NAME = "name"

    def __init__(self, repo="github/training-kit", db=None, webhook=None):
        self.repo = repo
        self.url = self.URL.format(repo=repo,endpoint="{endpoint}")
        super().__init__(db=db, webhook=webhook)

    def check_repo(self):
        result = dict({'repo': self.repo})
        # latest realease
        release = self.get_recent_repo(repo=self.repo)
        if release:
            if not self.release_exists(release=release):
                # if self.db:
                #     self.db.insert_(database.RELEASES, release)
                result.update(release)
        # latest commit on master branch
        commit = self.get_recent_commit_on_branch(repo=self.repo, branch='master')
        if commit:
            if not self.commit_exists(commit=commit):
                # if self.db:
                #     self.db.insert_(database.COMMITS, commit)
                # trigger build as push to github master branch
                response = self.trigger(branch="master")
                result.update(commit)
        # latest tag
        tag = self.get_recent_tag(repo=self.repo)
        if tag:
            if not self.tag_exists(tag=tag):
                # if self.db:
                #     self.db.insert_(database.TAGS, tag)
                # trigger build as push to github most_recent_tag branch
                response = self.trigger(branch="most_recent_tag")
                result.update(tag)

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
            tag_name = response.get(self.KEY_TAG_NAME, None)
            release_name = response.get(self.KEY_RELEASE_NAME, None)
            release = dict({'repo': repo,
                           'tag_name': tag_name,
                           'release_name': release_name})
            log.info('Latest release: {}'.format(release))
            return {"release": release}
        except (ValueError,
                NotFoundException,
                ApiRateLimitExceededException) as e:
            log.warn(e)

        return None

    def get_recent_commit_on_branch(self, repo, branch='master'):
        """Get the most recent commit on given branch.

        :param repo: github repository to check
        :param branch: branch to get most recent commit from
        :returns: most recent commit hash on given branch
        """
        endpoint = self.ENDPOINT_LATEST_COMMIT.format(branch=branch)
        try:
            response = self.request_json(self.url.format(endpoint=endpoint))
            commit_hash = self.get_commit_hash(response.get(self.KEY_COMMIT_NAME, None))
            commit = dict({'repo': repo, 'branch': branch, 'sha': commit_hash})
            log.info('Most recent commit: {}'.format(commit))
            return {"commit": commit}
        except (ValueError,
                NotFoundException,
                ApiRateLimitExceededException) as e:
            log.warn(e)

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
            commit_hash = self.get_commit_hash(response[0].get(self.KEY_COMMIT_NAME, None))
            tag = dict({'repo': repo, 'tag_name': tag_name, 'sha': commit_hash})
            log.info('Most recent tag: {}'.format(tag))
            return {"tag": tag}
        except (ValueError,
                NotFoundException,
                ApiRateLimitExceededException) as e:
            log.warn(e)

        return None


if __name__ == '__main__':
    db = database.Db(dbtype=database.SQLITE, dbname='data.db')

    news = list()
    xmr_daemon_trigger = DockerCloudWebHook(name="xmr_daemons", trigger_url="95ee9b9d-86a3-4d0d-97cb-6c7b55f5955b/trigger/80cdd7d9-669d-4392-b699-956468be9ef7/call/")
    repos = (
        ("monero-project/monero", xmr_daemon_trigger),
        ("aeonix/aeon", None),
    )
    for repo, webhook in repos:
        watcher = GithubWatcher(repo=repo, db=db, webhook=webhook)

        print(watcher.URL)
        print(watcher.url)
        print(watcher.repo)
        print(watcher.db)
        news.append(watcher.check_repo())

    #watcher = GithubWatcher(repo="monero-project/monero", db=db)
    #watcher.check_repo()
    #watcher = GithubWatcher(repo="monero-project/monero", db=db)
    #watcher.check_repo()

    # news = list()
    # repos = (
    #     'monero-project/monero',
    #     'moneroexamples/onion-monero-blockchain-explorer',
    #     'xmrig/xmrig',
    #     'aeonix/aeon',
    #     'sgerrand/alpine-pkg-glibc',
    #     'leev/ngx_http_geoip2_module',)
    # for repo in repos:
    #     news.append(check_repo(repo=repo, db=db))

    log.debug(news)
    for i, new in enumerate(news):
        if 'repo' in new:
            print(f"{i}" + ": " + new.get('repo'))
            del new['repo']
        if len(new) > 0:
            for k, v in new.items():
                print(" {key}: {value}".format(key=k, value=v))
        else:
            print('  no news')
