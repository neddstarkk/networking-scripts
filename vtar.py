import re


class VTAR():
    def rename(file_name):
        file_name = re.sub('[^0-9a-zA-Z]+', '\ ', file_name)