#!/bin/bash
#thenurhabib

sudo apt update -y
pip install argparse
pip install dnspython
pip install time
pip install asyncio
pip install aiohttp
git clone https://github.com/thenurhabib/subnum
cd subnum
sudo cp subnum.py /usr/bin
echo ""
echo "======================"
echo "installation complete."
echo "======================"