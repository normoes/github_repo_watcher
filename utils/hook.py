import logging

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class Hook:
    """A hook/event that can be triggered.
    """

    def __init__(self, name="", url=""):
        self.name = name
        self.url = url

    def event(self):
        log.info("event {name} on {url}".format(name=name, url=url))
