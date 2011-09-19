from db import *

con = mongo('127.0.0.1',27017, "pdfs", "test")
pres = con.find({"hash_data.file.md5":"0a3f7d7c339eb24d88727c326cc270df"}).count()
