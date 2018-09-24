from collections import namedtuple
from dateutil.parser import parse as parse_date
import hashlib
import json
import lxml.html
import os
import requests
import re
import shelve
import time
import urllib


def hash_256(data: bytes):
    """Compute the SHA2 256 Hash on some bytes."""
    return hashlib.sha256(data).hexdigest()


def filesize_to_string(size: int):
    """Return the file size in a human readable format."""
    suffixes = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB']
    while True:
        suffix = suffixes.pop(0)
        if size < 1024:
            break
        size /= 1024
    return '%d%s' % (round(size, 2), suffix)


class Dumper:
    class UnexpectedResponse(ValueError):
        """Error related to an invalid response."""
        pass

    class EmptyResponse(UnexpectedResponse):
        """Error related to an empty response."""
        pass

    class ParsingError(ValueError):
        pass

    class ReadAccessDenied(ValueError):
        pass

    class FileNotFound(ValueError):
        """The server responded with an NT_STATUS_OBJECT_NAME_NOT_FOUND error."""

    class File:
        """
        A Dumper.File stores meta information and is specified by a name and a dir_path.
        It also stores a URL pointing to the respective external file exposed to be fetched by the dumper.
        """

        def __init__(self, name: str, dir_path: str):
            self.name = name
            self.dir_path = dir_path
            # Attribute values will be set by dumper during dumping:
            self.date = None
            self.size = 0
            self.hash = None

        def __str__(self):
            return '<Dumper.File `%s` date:`%s` size:%s>' % (self.name, str(self.date), str(filesize_to_string(self.size)))

        def __eq__(self, other):
            return type(self) == type(
                other) and self.name == other.name and self.date == other.date and self.size == other.size

    class Directory:
        """A directory is used to store a tree of directories and files."""
        def __init__(self, name: str):
            self.name = name
            # Attribute values will be set by dumper during dumping:
            self.directories = None
            self.files = None
            self.info = ''
            self.path = ''  # Absolute path pointing at directory content: `/my/directory` (Contains no trailing slash)
            self.date = ''
            self.read_access = None
            self.error_info = None
            self.extracted_path = None

        @classmethod
        def from_directory_data(cls, html_response: str, queried_path: str, name: str = '[unnamed]',):
            """Create a directory by parsing the html response body of the directory listing."""
            self = cls(name=name)
            self.path = queried_path

            try:
                # print('Parsing response...')
                transformed_html = Dumper.gollem_string_filter(html_response)
                page = lxml.html.fromstring(transformed_html)

                page_title = Dumper.gollem_string_filter(page.xpath('//head/title/text()')[0])
                split = page_title.split(' :: ', 1)
                self.extracted_path = split[1]

                try:
                    access_denied_image = page.xpath('//body/ul[@class="notices"]/li/'
                                            'img[@src="/horde3/themes/graphics/alerts/error.png"]')[0]
                    self.error_info = page.xpath('//body/ul[@class="notices"]/li/text()')[0]
                    # No error indicating that access has been denied
                    self.read_access = False
                    return self
                except IndexError:
                    self.read_access = True

                self.files = []
                self.directories = []
                try:
                    file_table = page.xpath('//body/form/table[@id="filelist"]')[0]
                except IndexError:
                    # The directory appears to be empty because the file list table was not found.
                    return self

                self.info = file_table.xpath('.//caption/text()')[0]

                rows = file_table.xpath('.//tr')

                # Convert each row of information into a File or Directory

                for row in rows:
                    if len(row.xpath('.//th')) > 0:
                        # Skip rows with header (<tr><th></th><tr>) else the xpath below will fail
                        continue

                    # COLLECT DATA (Parse html)
                    name = row.xpath('.//input[@class="checkbox"]/@value')[0]

                    is_directory = bool(row.xpath('.//input[@name="itemTypes[]"]/@value')[0] == '**dir')

                    extracted_date_string = row.xpath('(.//td)[last()-1]/text()')[0]
                    date = parse_date(extracted_date_string)

                    # CREATE OBJECTS
                    if is_directory:
                        directory = Dumper.Directory(name)
                        directory.date = date
                        directory.path = self.path.rstrip('/') + '/' + directory.name
                        self.directories.append(directory)
                    else:
                        extracted_size_string = row.xpath('(.//td)[last()]/text()')[0]
                        cleaned_size_string = ''.join([c for c in extracted_size_string if c.isdigit()])
                        file_size = int(cleaned_size_string) if cleaned_size_string else 0

                        file = Dumper.File(name, self.path)
                        file.date = date
                        file.size = file_size

                        self.files.append(file)

                return self

            except (AssertionError, ValueError, IndexError, KeyError) as e:
                raise Dumper.ParsingError('Parsing the directory listing for directory ´%s´ failed.' %
                                          self.path,
                                          html_response, e)

        def __str__(self):
            """Print the Directory's name, path, subdir- and file count."""
            dir_count = len(self.directories) if self.directories else None
            file_count = len(self.files) if self.files else None
            additional_info = ''
            if self.read_access is False:
                additional_info += ', No Read Access'
            return '<Dumper.Directory `%s` @ `%s` #directories: %s, #files: %s%s>' \
                   % (self.name, self.path, str(dir_count), str(file_count), additional_info)

        def list_all(self):
            """Print all useful information of a Directory. This includes a list of all files and directories."""
            print(self)

            if self.directories:
                print(' ~~~ Sub-Directories ~~~')
                for directory in self.directories:
                    print(directory)
            if self.files:
                print(' ~~~ Files ~~~')
                for file in self.files:
                    print(file)

    def __init__(self, host: str, ssl_check: bool = True):
        """Allows to view and download files from the exposed file system structure after authentication."""
        # Define general constants
        self.logged_in = False
        self.host = host
        self.user = None
        self.session = requests.Session()

        # Option to ignore SSL warnings if host exposes wrong certificates
        self.ssl_check = ssl_check
        if not self.ssl_check:
            # Disable insecure SSL warnings
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        # Always store the recent most response for debugging purpose
        self.recent_response = None

    def request(self, url: str, method: str = 'GET', data: json = None, follow_redirects: bool = True):
        """Helper for self implemented post() and get()."""
        if url.startswith('/'):
            url = self.host + url
        # print('requesting url `%s`' % url)
        self.recent_response = self.session.request(
            method,
            url,
            verify=self.ssl_check,
            data=data,
            allow_redirects=follow_redirects
        )
        return self.recent_response

    def login(self, username: str, password: str):
        """Create an authorized session with the given credentials."""
        self.user = username
        self.session = requests.Session()
        form = {
            'actionID': '',
            'url': '',
            'load_frameset': '1',
            'autologin': '0',
            'anchor_string': '',
            'server_key': 'cyrus',
            'imapuser': username,
            'pass': password,
            'new_lang': 'de_DE',  # Important! Else unicode containing äöü and similar will be broken
            'loginButton': 'Anmelden',
        }

        r = self.request('/horde3/imp/redirect.php', method='POST', data=form, follow_redirects=False)

        if 'Location' not in r.headers:
            raise Dumper.UnexpectedResponse(r, 'Response does not contain `Location`-header')

        # Check if login was successful
        logged_in = 'horde_logout' not in r.headers['Location']
        if not logged_in:
            print('Login failed')
            self.logged_in = False
            return False
        else:
            print('Login successful')
            self.logged_in = True

        # Check if the server requests a maintenance during login
        maintenance_requested = 'maintenance.php' in r.headers['Location']
        print('Maintenance requested:', maintenance_requested)

        self.obtain_gollem_cookie()

        return True

    def obtain_gollem_cookie(self):
        """
        Retrieve an authorized gollem cookie to access the gollem virtual file system interface.
        ( Login must still be valid in order to retrieve an authorized gollem cookie! )
        """
        if self.session.cookies.get('gollem_key'):
            print('There is a gollem_key in the current session cookies already.')
            print('No request made.')
            return False

        # This requests will receive an server side generated gollem_key cookie if it does not exist
        print('Acquiring gollem_key cookie...')
        r = self.request('/horde3/gollem/login.php?backend_key=smb&change_backend=1', follow_redirects=True)
        gollem_key = self.session.cookies.get('gollem_key')

        if not gollem_key:
            raise Dumper.UnexpectedResponse(r, 'Obtaining gollem_key cookie FAILED.')
        else:
            print('Obtained gollem_key cookie:', gollem_key)
            return gollem_key

    @staticmethod
    def gollem_string_filter(text: str = ''):
        """Transform strings into a sensible form."""
        text = text.replace('\u00a0', ' ')  # Replace non-breaking space by the normal space U+0020
        return text

    def download_file(self, file: File, blob_dir='./snapshot-blobs'):
        """
        Download and save a local copy of the external file specified by the Dumper.File object.
        The file will be saved within the blob_dir and its name is the SHA2 256 hash of its binary content.
        """
        '''
        # Second API access point that appears to be slower and is therefore not used in this project
        params = (
            ('actionID', 'view_file'),
            ('file', file.name),
            ('dir', file.dir_path),
            ('driver', 'smb'),
        )
        url = self.host + '/horde3/gollem/view.php'
        '''

        file_path = file.dir_path.rstrip('/') + '/' + file.name
        print('Downloading file `%s`' % file_path)

        params = (
            ('module', 'gollem'),
            ('actionID', 'download_file'),
            ('file', file.name),
            ('dir', file.dir_path),
            ('driver', 'smb')
        )
        url = self.host + '/horde3/services/download/'
        r = self.session.get(url, stream=True, proxies=self.proxy, allow_redirects=True, verify=self.ssl_check,
                             params=params)
        self.recent_response = r
        if r.status_code != 200:
            raise Dumper.UnexpectedResponse(r, 'File download failed.')

        # print([str(h) for h in r.history])
        local_tmp_name = './tmp_download/%s' % hash_256(file_path.encode())
        with open(local_tmp_name, 'w+b') as handle:
            hashsum = hashlib.sha256()
            for data in r.iter_content():
                handle.write(data)
                hashsum.update(data)

        file.hash = hashsum.hexdigest()
        local_name = blob_dir.rstrip('/') + '/' + file.hash
        if os.path.isfile(local_name):
            print('File %s does already exist!' % local_name)
            os.remove(local_tmp_name)
        else:
            os.rename(local_tmp_name, local_name)

        return file

    def fetch_directory(self, dirpath: str = ''):
        """Send an authenticated request to the sever to fetch the directory and a list of its contents."""
        dirpath = dirpath.rstrip('/')
        if not dirpath:
            dirpath = '/'
        print('Requesting directory contents of `[ROOT]%s`...' % dirpath)

        encoded_dirpath = urllib.parse.quote_plus(dirpath, safe='/', encoding='utf-8')  # URL-encode the directory path
        r = self.request('/horde3/gollem/manager.php?dir=%s' % encoded_dirpath)

        if not r.content:
            raise Dumper.EmptyResponse(r, 'Unexpected response for directory listing of ' + dirpath)

        directory = Dumper.Directory.from_directory_data(r.text, dirpath)

        if directory.error_info:
            if 'NT_STATUS_OBJECT_NAME_NOT_FOUND' in directory.error_info:
                raise Dumper.FileNotFound(directory.error_info, directory)

        return directory

    def complement_directory(self, dir: Directory):
        """Combine the meta information about a directory from two different server responses."""
        content_listing_dir = self.fetch_directory(dir.path)
        dir.directories = content_listing_dir.directories
        dir.files = content_listing_dir.files
        return dir

    def create_snapshot(self, root_dir: Directory, exclude_list=None, use_cache=True, excluded_characters='\\/:*?"<>|'):
        """Create an archive of the HordeFilesystem structure currently accessible."""
        snap_name = '%s_%s_%s' % (self.host.split('://')[1], self.user, str(time.time()))
        sanitized_snap_name = re.sub('[%s]' % excluded_characters, '', snap_name)

        def directory_is_excluded(path: str):
            """Determine if the given path is excluded by the snapshot exclude list."""
            if exclude_list:
                for exclude_regex in exclude_list:
                    if re.fullmatch(exclude_regex, path, re.IGNORECASE):
                        print('The directory %s is excluded because it matches exclude rule %s' % (path, exclude_regex))
                        return True
            return False

        snap = HordeFilesystem.Snapshot(sanitized_snap_name, root_dir.path, exclude_list)
        snap.start_date = time.time()
        file_count = 0
        dir_depth = 0

        def archive_directory(dir: Dumper.Directory):
            """Recursively create an index of the external server traversing down the given directory."""
            nonlocal file_count
            nonlocal dir_depth
            print('Archiving directory %s' % str(dir))

            if dir.files is not None:
                for file in dir.files:
                    # archive dumped data in snapshot register
                    snap._archive_file(file)
                    file_count += 1
                print('Currently archived meta information about %d files.' % file_count)

            if dir.directories is not None:
                dir_depth += 1
                for subdirectory in dir.directories:
                    # recursively dump directories
                    if not directory_is_excluded(subdirectory.path):
                        print('Dumper directory depth: %d' % dir_depth)
                        print('Subdir `%s` not excluded. Fetching dir contents…' % subdirectory.path)
                        subdirectory = self.complement_directory(subdirectory)
                        archive_directory(subdirectory)
                dir_depth -= 1

        archive_directory(root_dir)
        snap.end_date = time.time()
        return snap


class HordeFilesystem:
    class Snapshot:
        """An object for storing an dict containing all indexed files as well as information about the index itself."""
        def __init__(self, name: str, root_path: str, exclude_list: str):
            self.filesystem = shelve.open('snapshots/%s' % name)
            self.start_date = None
            self.end_date = None
            self.root_path = root_path
            self.exclude_list = exclude_list

        def _get_file(self, file: str):
            """Retrieve the snapshot Dumper.File object specified by its path."""
            try:
                return self.filesystem[file]
            except KeyError:
                raise FileNotFoundError('The file does not exist in the current snapshot.', file)

        def _archive_file(self, file: Dumper.File):
            """Save a snapshot Dumper.File object under the given path."""
            path = file.dir_path + '' + file.name  # TODO check file path separator
            self.filesystem[path] = file

        def open(self, file: str, mode='r'):
            """Create a file handle for a local copy of the external file specified by its external path."""
            if mode not in ['r', 'rb']:
                raise ValueError('The specified mode is not supported.')

            file_hash = self._get_file(file).hash

            if file_hash is None:
                raise IOError('The file has not been downloaded and is therefore unavailable for reading.')
            return open('snapshots/blobs/%s' % file_hash, mode)

        def stat(self, file: str):
            """Retrieve the cached meta information of an external file specified by its external path."""
            dumper_file = self._get_file(file)
            """(mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime)"""
            StatResult = namedtuple('StatResult', ['st_size', 'st_mtime', ])
            return StatResult(st_size=dumper_file.size, st_mtime=dumper_file.date)

        def list_files(self):
            """List all files archived in the snapshot."""
            print('The following items are archived in the current snapshot.')
            for path, meta_file in self.filesystem.items():
                print(path, meta_file)

    def __init__(self, name: str):
        self.snapshots = shelve.open('filesystem-%s' % name)

    def list_snapshots(self):
        """Display a list of all snapshots made."""
        print('The following snapshots are available of the currently selected filesystem.')
        for snap_name in self.snapshots.items():
            print(snap_name)

    def select_snapshot(self, snap_id):
        """Return a snapshot which is specified by its exact initialization time and date."""
        pass


if __name__ == '__main__':
    """Login to the server with credentials provided by settings.json. Then login and index the external root 
    recursively."""

    with open('settings.json', 'r') as settings_handle:
        settings = json.load(settings_handle)

    if not (settings['host'] and settings['username'] and settings['password']):
        print('Please enter host, username and password in the settings.json file.')
        exit(1)

    dumper = Dumper(settings['host'], ssl_check=False)
    logged_in = dumper.login(settings['username'], settings['password'])
    print('Logged in: %r' % logged_in)

    root_directory = dumper.fetch_directory('')
    snap = dumper.create_snapshot(root_directory, exclude_list=settings['exclude_list'])
