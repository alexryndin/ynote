<p align="center"><img width=12.5% src="https://github.com/alexryndin/ynote/blob/master/readme/ynote_logo.png"></p>

# ynote
Notes keeping system (and maybe more)
## I wanna try
```
# Initialize db, ~/ynote.db by default
./init_db.sh
docker pull rlambda/ynote
docker run -ti -v ~/.ynote.db:/main.db -p 8080:8080 -v $(pwd)/example_conf.lua:/ynote.lua rlambda/ynote
```
