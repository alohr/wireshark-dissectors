### Install Qt5 on MacOS

```
brew install qt5
brew link --force qt5

# check version
ls -l /usr/local/Cellar/qt5/5.6.1-1/mkspecs

# create symlinks
sudo ln -s /usr/local/Cellar/qt5/5.6.1-1/mkspecs /usr/local/mkspecs
sudo ln -s /usr/local/Cellar/qt5/5.6.1-1/plugins /usr/local/plugins
```

https://wiki.wireshark.org/BuildingAndInstalling
