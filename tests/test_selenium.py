from selenium import webdriver
from selenium.common.exceptions import WebDriverException

from mailpile.httpd import HttpWorker
from tests import MailPileUnittest, get_shared_mailpile


class MailPileSeleniumTest(MailPileUnittest):

    DRIVER = None

    def __init__(self, *args, **kwargs):
        MailPileUnittest.__init__(self, *args, **kwargs)

    def setUp(self):
        self.driver = MailPileSeleniumTest.DRIVER

    def tearDown(self):
        try:
            self.driver.close()
        except WebDriverException:
            pass

    @classmethod
    def _start_web_server(cls):
        mp = get_shared_mailpile()
        config = mp._config
        session = mp._session
        sspec = (config.sys.http_host, config.sys.http_port)
        cls.http_worker = config.http_worker = HttpWorker(session, sspec)
        config.http_worker.start()

    @classmethod
    def _start_selenium_driver(cls):
        if not cls.DRIVER:
            driver = webdriver.PhantomJS()  # or add to your PATH
            driver.set_window_size(1024, 768)  # optional
            cls.DRIVER = driver

    @classmethod
    def _stop_selenium_driver(cls):
        if cls.DRIVER:
            cls.DRIVER.quit()
            cls.DRIVER = None

    @classmethod
    def setUpClass(cls):
        cls._start_selenium_driver()
        cls._start_web_server()

    @classmethod
    def _stop_web_server(cls):
        try:
            cls.http_worker.quit()
        except WebDriverException:
            pass

    @classmethod
    def tearDownClass(cls):
        cls._stop_web_server()
        cls._stop_selenium_driver()

    def go_to_mailpile_home(self):
        self.driver.get('http://localhost:33411/')

    def take_screenshot(self, filename):
        self.driver.save_screenshot(filename)  # save a screenshot to disk

    def dump_source_to(self, filename):
        with open(filename, 'w') as out:
            out.write(self.driver.page_source.encode('utf8'))

    def navigate_to(self, name):
        contacts = self.driver.find_element_by_xpath('//a[@alt="%s"]/span' % name)
        self.assertTrue(contacts.is_displayed())
        contacts.click()

    def test_foobar(self):
        self.go_to_mailpile_home()
        self.take_screenshot('screen.png')  # save a screenshot to disk
        self.dump_source_to('source.html')

        self.navigate_to('Contacts')

        self.driver.save_screenshot  ('screen2.png')  # save a screenshot to disk\
        self.assertIn('Contacts', self.driver.title)

    def test_go_to_contacts(self):
        pass
