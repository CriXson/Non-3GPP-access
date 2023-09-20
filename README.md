## Description

This UE can be used to test the authentication of the Open5GS core via the N3IWF. The authentication mechanisms 5G-AKA and EAP-TLS are supported.
The UE is forked from [my5G-non3GPP-access](https://github.com/my5G/my5G-non3GPP-access).

## Documentation

To create the required ipsec link.

```console
ip link add ipsec0 type vti local LOCAL_UE_IP remote N3IWF_IP key 5
ip link set ipsec0 up
``` 

To start the UE.

```console
sudo ./bin/ue_both
``` 

To build the UE.

```console
go build -o bin/ue -x src/ue/ue.go
``` 

To trigger the registration process.

```console
cd src/ue/
./trigger_initial_registration_tls.sh
``` 

To trigger any test.

```console
cd ue_tests
./TestTLS100.sh
``` 

For more detailed manual, please reference the my5G-non3GPP-access [Wiki](https://github.com/my5G/my5G-non3GPP-access/wiki).

## License

Apache 2.0
