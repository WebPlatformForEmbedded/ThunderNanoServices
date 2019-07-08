-----------------
Build:

bitbake displaysettings

or locally (my example)

cd displaysettings 
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/home/mark/rdk/wpe/install ..
make
make install

-----------------
Install:

cp
tmp/work/cortexa15t2hf-neon-rdk-linux-gnueabi/displaysettings/3.0+gitAUTOINC+70c598136c-r0/git/DisplaySettings.json
to 
/etc/WPEFramework/plugins/DisplaySettings.json

cp
tmp/work/cortexa15t2hf-neon-rdk-linux-gnueabi/displaysettings/3.0+gitAUTOINC+70c598136c-r0/package/usr/lib/wpeframework/plugins/libWPEFrameworkDisplaySettings.so
to
/usr/lib/wpeframework/plugins/libWPEFrameworkDisplaySettings.so

systemctl restart wpeframework

-----------------
Test:

curl --header "Content-Type: application/json" --request POST --data '{"jsonrpc":"2.0","id":"3","method": "DisplaySettings.1.getConnectedVideoDisplays"}' http://127.0.0.1:3331/jsonrpc
