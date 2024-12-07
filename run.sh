if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi


export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

./xdp-counter "$@"