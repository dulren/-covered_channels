```bash
vagrant up
vagrant ssh uz
python3 ./uz.py --listen-ip 0.0.0.0 --listen-port 9000 --forward-ip 192.168.56.13 --forward-port 9001
vagrant ssh p2
python3 ./p2.py --listen-ip 0.0.0.0 --listen-port 9001 --interval 1.0 --covert-output ./covert.txt --legit-output ./main.txt
vagrant ssh p1
python3 ./p1.py --main-file ./main.txt --covert-file ./covered.txt --dst-ip 192.168.56.12 --dst-port 9000 --interval 1.0
```
