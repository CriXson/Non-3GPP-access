package ue_procedures

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"free5gc/lib/CommonConsumerTestData/UDM/TestGenAuthData"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasTestpacket"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/nas/security"
	"free5gc/lib/openapi/models"
	"free5gc/src/n3iwf/context"
	"free5gc/src/n3iwf/ike/handler"
	"free5gc/src/n3iwf/ike/message"
	"github.com/google/gopacket"
	"log"
	"math/big"
	"os"
	"time"

	//"free5gc/src/ue/ue_ike/ike_message"
	"github.com/sirupsen/logrus"
	"hash"
	"net"

	"free5gc/src/ue/logger"
	"free5gc/src/ue/ue_context"
	//"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

var pingLog *logrus.Entry

var eapReqGlobal *message.EAP

var ueGlobal *UeRanContext
var mobileIdentity5GSGlobal nasType.MobileIdentity5GS
var n3iwfUDPAddrGlobal *net.UDPAddr
var udpConnectionGlobal *net.UDPConn
var localNonceGlobal []byte
var nonceGlobal *message.Nonce
var ikeSecurityAssociationGlobal *context.IKESecurityAssociation
var eapIdentifierGlobal uint8

func init() {
	pingLog = logger.RunLog
}

func createIKEChildSecurityAssociation(chosenSecurityAssociation *message.SecurityAssociation) (*context.ChildSecurityAssociation, error) {
	childSecurityAssociation := new(context.ChildSecurityAssociation)

	if chosenSecurityAssociation == nil {
		return nil, errors.New("chosenSecurityAssociation is nil")
	}

	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, errors.New("No proposal")
	}

	childSecurityAssociation.SPI = binary.BigEndian.Uint32(chosenSecurityAssociation.Proposals[0].SPI)

	if len(chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm) != 0 {
		childSecurityAssociation.EncryptionAlgorithm = chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm) != 0 {
		childSecurityAssociation.IntegrityAlgorithm = chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers) != 0 {
		if chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers[0].TransformID == 0 {
			childSecurityAssociation.ESN = false
		} else {
			childSecurityAssociation.ESN = true
		}
	}

	return childSecurityAssociation, nil
}

func getAuthSubscription() (authSubs models.AuthenticationSubscription) {
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: TestGenAuthData.MilenageTestSet19.K,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: TestGenAuthData.MilenageTestSet19.OPC,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: TestGenAuthData.MilenageTestSet19.OP,
		},
	}
	authSubs.AuthenticationManagementField = "8000"

	authSubs.SequenceNumber = TestGenAuthData.MilenageTestSet19.SQN
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return
}

func setupUDPSocket(ctx *ue_context.UEContext, log *logrus.Entry) *net.UDPConn {
	bindAddr := fmt.Sprintf("%s:500", ctx.IKEBindAddress)
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		log.Fatal("Resolve UDP address failed")
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Listen UDP socket failed: %+v", err)
	}
	return udpListener
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}

func generateKeyForIKESA(ikeSecurityAssociation *context.IKESecurityAssociation) error {
	// Transforms
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int
	var ok bool

	length_SK_d = 20
	length_SK_ai = 20
	length_SK_ar = length_SK_ai
	length_SK_ei = 32
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = handler.NewPseudorandomFunction(ikeSecurityAssociation.ConcatenatedNonce, transformPseudorandomFunction.TransformID); !ok {
		return errors.New("New pseudorandom function failed")
	}

	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.DiffieHellmanSharedKey); err != nil {
		return errors.New("Pseudorandom function write failed")
	}

	SKEYSEED := pseudorandomFunction.Sum(nil)

	seed := concatenateNonceAndSPI(ikeSecurityAssociation.ConcatenatedNonce, ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = handler.NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	// Assign keys into context
	ikeSecurityAssociation.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	ikeSecurityAssociation.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	ikeSecurityAssociation.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	ikeSecurityAssociation.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	ikeSecurityAssociation.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	ikeSecurityAssociation.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	ikeSecurityAssociation.SK_pr = keyStream[:length_SK_pr]
	keyStream = keyStream[length_SK_pr:]

	return nil
}

func generateKeyForChildSA(ikeSecurityAssociation *context.IKESecurityAssociation, childSecurityAssociation *context.ChildSecurityAssociation) error {
	// Transforms
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction
	var transformIntegrityAlgorithmForIPSec *message.Transform
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm) != 0 {
		transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm[0]
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int
	var ok bool

	lengthEncryptionKeyIPSec = 32
	if transformIntegrityAlgorithmForIPSec != nil {
		lengthIntegrityKeyIPSec = 20
	}
	totalKeyLength = lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec
	totalKeyLength = totalKeyLength * 2

	// Generate key for child security association as specified in RFC 7296 section 2.17
	seed := ikeSecurityAssociation.ConcatenatedNonce
	var pseudorandomFunction hash.Hash

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = handler.NewPseudorandomFunction(ikeSecurityAssociation.SK_d, transformPseudorandomFunction.TransformID); !ok {
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	childSecurityAssociation.InitiatorToResponderEncryptionKey = append(childSecurityAssociation.InitiatorToResponderEncryptionKey, keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.InitiatorToResponderIntegrityKey = append(childSecurityAssociation.InitiatorToResponderIntegrityKey, keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorEncryptionKey = append(childSecurityAssociation.ResponderToInitiatorEncryptionKey, keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorIntegrityKey = append(childSecurityAssociation.ResponderToInitiatorIntegrityKey, keyStream[:lengthIntegrityKeyIPSec]...)

	return nil

}

func decryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikeMessage *message.IKEMessage, encryptedPayload *message.Encrypted) ([]message.IKEPayloadType, error) {
	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength := 12 // HMAC_SHA1_96

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ikeMessageData, err := message.Encode(ikeMessage)
	if err != nil {
		return nil, errors.New("Encoding IKE message failed")
	}

	ok, err := handler.VerifyIKEChecksum(ikeSecurityAssociation.SK_ar, ikeMessageData[:len(ikeMessageData)-checksumLength], checksum, transformIntegrityAlgorithm.TransformID)
	if err != nil {
		return nil, errors.New("Error verify checksum")
	}
	if !ok {
		return nil, errors.New("Checksum failed, drop.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := handler.DecryptMessage(ikeSecurityAssociation.SK_er, encryptedData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		return nil, errors.New("Error decrypting message")
	}

	decryptedIKEPayload, err := message.DecodePayload(encryptedPayload.NextPayload, plainText)
	if err != nil {
		return nil, errors.New("Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil

}

func encryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikePayload []message.IKEPayloadType, responseIKEMessage *message.IKEMessage) error {
	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength := 12 // HMAC_SHA1_96

	// Encrypting
	notificationPayloadData, err := message.EncodePayload(ikePayload)
	if err != nil {
		return errors.New("Encoding IKE payload failed.")
	}

	encryptedData, err := handler.EncryptMessage(ikeSecurityAssociation.SK_ei, notificationPayloadData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		return errors.New("Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	responseEncryptedPayload := message.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	responseIKEMessage.IKEPayload = append(responseIKEMessage.IKEPayload, responseEncryptedPayload)

	// Calculate checksum
	responseIKEMessageData, err := message.Encode(responseIKEMessage)
	if err != nil {
		return errors.New("Encoding IKE message error")
	}
	checksumOfMessage, err := handler.CalculateChecksum(ikeSecurityAssociation.SK_ai, responseIKEMessageData[:len(responseIKEMessageData)-checksumLength], transformIntegrityAlgorithm.TransformID)
	if err != nil {
		return errors.New("Error calculating checksum")
	}
	checksumField := responseEncryptedPayload.EncryptedData[len(responseEncryptedPayload.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil

}

func buildEAP5GANParameters() []byte {
	var anParameters []byte

	// Build GUAMI
	anParameter := make([]byte, 2)
	guami := make([]byte, 6)
	guami[0] = 0x00
	guami[1] = 0xf1
	guami[2] = 0x10
	guami[3] = 0x02
	guami[4] = 0x00
	guami[5] = 0x40
	anParameter[0] = message.ANParametersTypeGUAMI
	anParameter[1] = byte(len(guami))
	anParameter = append(anParameter, guami...)

	anParameters = append(anParameters, anParameter...)

	// Build Establishment Cause
	anParameter = make([]byte, 2)
	establishmentCause := make([]byte, 1)
	establishmentCause[0] = message.EstablishmentCauseMO_Data
	anParameter[0] = message.ANParametersTypeEstablishmentCause
	anParameter[1] = byte(len(establishmentCause))
	anParameter = append(anParameter, establishmentCause...)

	anParameters = append(anParameters, anParameter...)

	// Build PLMN ID
	anParameter = make([]byte, 2)
	plmnID := make([]byte, 3)
	plmnID[0] = 0x00
	plmnID[1] = 0x01
	plmnID[2] = 0x01
	anParameter[0] = message.ANParametersTypeSelectedPLMNID
	anParameter[1] = byte(len(plmnID))
	anParameter = append(anParameter, plmnID...)

	anParameters = append(anParameters, anParameter...)

	// Build NSSAI
	anParameter = make([]byte, 2)
	nssai := make([]byte, 2)
	/*
		snssai := make([]byte, 4)
		snssai[0] = 0x01
		snssai[1] = 0x00
		snssai[2] = 0x00
		snssai[3] = 0x01
		nssai = append(nssai, snssai...)
		snssai = make([]byte, 4)
		snssai[0] = 0x01
		snssai[1] = 0xff
		snssai[2] = 0xff
		snssai[3] = 0xff
		nssai = append(nssai, snssai...)
	*/
	nssai[0] = 0x01
	nssai[1] = 0x02
	anParameter[0] = message.ANParametersTypeRequestedNSSAI
	anParameter[1] = byte(len(nssai))
	anParameter = append(anParameter, nssai...)

	anParameters = append(anParameters, anParameter...)

	return anParameters
}

func parseIPAddressInformationToChildSecurityAssociation(
	childSecurityAssociation *context.ChildSecurityAssociation,
	n3iwfPublicIPAddr net.IP,
	ikeBindAddr string,
	trafficSelectorLocal *message.IndividualTrafficSelector,
	trafficSelectorRemote *message.IndividualTrafficSelector) error {

	if childSecurityAssociation == nil {
		return errors.New("childSecurityAssociation is nil")
	}

	childSecurityAssociation.PeerPublicIPAddr = n3iwfPublicIPAddr
	childSecurityAssociation.LocalPublicIPAddr = net.ParseIP(ikeBindAddr)

	childSecurityAssociation.TrafficSelectorLocal = net.IPNet{
		IP:   trafficSelectorLocal.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	childSecurityAssociation.TrafficSelectorRemote = net.IPNet{
		IP:   trafficSelectorRemote.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	return nil
}

func applyXFRMRule(ue_is_initiator bool, childSecurityAssociation *context.ChildSecurityAssociation) error {
	// Build XFRM information data structure for incoming traffic.

	// Mark
	mark := &netlink.XfrmMark{
		Value: 5,
	}

	// Direction: N3IWF -> UE
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if ue_is_initiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: handler.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: handler.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: handler.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: handler.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.InitiatorToResponderIntegrityKey,
			}
		}
	}

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSecurityAssociation.SPI)
	xfrmState.Mark = mark
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.ESN

	// Commit xfrm state to netlink
	var err error
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	if childSecurityAssociation.SelectedIPProtocol == 0 {
		return errors.New("Protocol == 0")
	}

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Mark = mark
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}

	// Direction: UE -> N3IWF
	// State
	if ue_is_initiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src

	// Commit xfrm state to netlink
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}

	return nil
}
func InitialRegistrationProcedureTLS(ueContext *ue_context.UEContext, rec *Record) {
	defer measureTime("EAP-TLS time", rec)()
	authStarted("Auth_started_counter")
	rec.errors = 0
	rec.paketRetransmission = 0
	err, ikeMessage, ok, ikeMessageData, buffer,
		n, ikePayload, encryptedPayload, decryptedIKEPayload, eapVendorTypeData, ueSecurityCapability,
		nasLength, eapExpanded, eap, _, decodedNAS := initialIkeandNGAP(ueContext, rec)

	log.Printf("not used: ", ueGlobal, mobileIdentity5GSGlobal, err, ikeMessage, ok, localNonceGlobal, nonceGlobal, ikeMessageData, buffer,
		n, ikePayload, encryptedPayload, decryptedIKEPayload, eapVendorTypeData, ueSecurityCapability, nasLength, eap)
	// Decode NAS - Authentication Request
	nasData := eapExpanded.VendorData[4:]
	decodedNAS = new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}

	eapMessage := decodedNAS.AuthenticationRequest.GetEAPMessage()
	pingLog.Infof("eapMessage TLS START: %d", eapMessage)
	eapID := eapMessage[1]
	pingLog.Infof("eapID : %d", eapID)

	resp := nasMessage.NewAuthenticationResponse(1)
	resp.ExtendedProtocolDiscriminator = nasType.ExtendedProtocolDiscriminator{Octet: 126}
	resp.SpareHalfOctetAndSecurityHeaderType = nasType.SpareHalfOctetAndSecurityHeaderType{Octet: 0}
	resp.AuthenticationResponseMessageIdentity = nasType.AuthenticationResponseMessageIdentity{Octet: 87}

	Client()
	engineState := GetEngineState()
	log.Printf("1 SSL enginge state", engineState)
	tlsRec, tlsMessageLength, fragmentsCount, err := ReadFromServer()
	log.Printf("Fragmentcount: ", fragmentsCount)
	log.Printf("TLSMessageLength: ", tlsMessageLength)
	log.Printf("TLSREC len: ", len(tlsRec[0]))
	engineState = GetEngineState()
	log.Printf("2 SSL enginge state", engineState)
	errCode := GetLastErroCode()
	log.Printf(" Last Error code engine", errCode)
	engineState = GetEngineState()
	log.Printf("SSL enginge state", engineState)
	eapMessageOut := createEAPMessage(tlsRec, eapID)
	resp.EAPMessage = &eapMessageOut
	bufferResp := new(bytes.Buffer)
	resp.EncodeAuthenticationResponse(bufferResp)
	var ikeMessageID uint32 = 3
	err = writeToN3IWF(ikeSecurityAssociationGlobal, bufferResp, udpConnectionGlobal, n3iwfUDPAddrGlobal, ikeMessageID, rec)
	rec.startTime = time.Now()
	ikeMessageID++

	eapID = handshake(resp, udpConnectionGlobal, ikeSecurityAssociationGlobal, n3iwfUDPAddrGlobal, &ikeMessageID, rec)
	if eapID == 0 {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		log.Fatalf("eap id 0 after handhsake")
	}
	eapACK := createEAPACK(eapID)
	log.Printf("SSL enginge state after Reading from bearSSL %d", GetEngineState())
	resp.EAPMessage = &eapACK
	bufferResp = new(bytes.Buffer)
	resp.EncodeAuthenticationResponse(bufferResp)
	rec.startTime = time.Now()
	writeToN3IWF(ikeSecurityAssociationGlobal, bufferResp, udpConnectionGlobal, n3iwfUDPAddrGlobal, ikeMessageID, rec)
	ikeMessageID++
	//EAP SUCESS
	nasData = replayN3IWF(udpConnectionGlobal, ikeSecurityAssociationGlobal, rec)
	rec.addToRtt(time.Since(rec.startTime))
	decodedNAS = new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}

	eapMessage = decodedNAS.AuthenticationRequest.GetEAPMessage()
	pingLog.Infof("eapMessage TLS START: %d", eapMessage)
	eapID = eapMessage[1]
	pingLog.Infof("eapID : %d", eapID)
	pingLog.Infof("eapReqGlobal.Code : %d", eapMessage[0])
	if eapMessage[0] == message.EAPCodeSuccess {
		pingLog.Info(" --------------------- EAP-TLS done -----------------------------")
		emsk := GetEMSK()
		pingLog.Infof("EMSK: %d", emsk)
	} else {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("NO EAP SUCCESS ")
	}
}

func measureTime(funcName string, rec *Record) func() {
	start := time.Now()
	return func() {
		duration := time.Since(start)
		pingLog.Infof("------------------------------------------------------------------------------------------------\nTime taken by %s function is %v \n", funcName, duration)
		rec.authenticationDuration = duration.String()
	}
}

func writeToN3IWF(ikeSecurityAssociation *context.IKESecurityAssociation, bufferResp *bytes.Buffer,
	udpConnection *net.UDPConn, n3iwfUDPAddr *net.UDPAddr, ikeMessageID uint32, rec *Record) error {
	// IKE_AUTH - EAP exchange
	ikeMessage := message.BuildIKEHeader(123123, ikeSecurityAssociation.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, ikeMessageID)

	ikePayload := []message.IKEPayloadType{}

	// EAP-5G vendor type data
	eapVendorTypeData := make([]byte, 4)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// NAS - Authentication Response
	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(bufferResp.Bytes())))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, bufferResp.Bytes()...)

	//pingLog.Infof("bufferResp.Bytes(): %d ", bufferResp.Bytes())

	eapExpanded := message.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)
	pingLog.Infof("eapReqGlobal identifier: %d", eapReqGlobal.Identifier)
	eap := message.BuildEAP(message.EAPCodeResponse, eapReqGlobal.Identifier, eapExpanded)
	pingLog.Infoln("SENDING TO UE")
	//pingLog.Infof("EAP in WriteN3IWF: %d ", eap)
	ikePayload = append(ikePayload, eap)

	err := encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}

	// Send to N3IWF
	ikeMessageData, err := message.Encode(ikeMessage)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}

	pingLog.Infof("n3iwfUDPAddr: %d:%p", n3iwfUDPAddr.IP, n3iwfUDPAddr.Port)
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	rec.paketCounter++
	return err
}

func replayN3IWF(udpConnection *net.UDPConn, ikeSecurityAssociation *context.IKESecurityAssociation, rec *Record) []byte {
	// Receive N3IWF reply
	buffer := make([]byte, 65535)
	var n int
	var err error
	pingLog.Printf("local address: %d", udpConnection.LocalAddr())
	for i := 0; i < 5; i++ {
		n, _, err = udpConnection.ReadFromUDP(buffer)
		if n != 0 {
			break
		}
		if err != nil {
			rec.errors++
			rec.errorReason = err.Error()
			rec.WriteToCSV(rec.filename)
			pingLog.Fatal(err)
		}
	}

	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}

	ikeMessage, err := message.Decode(buffer[:n])
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	encryptedPayload, ok := ikeMessage.IKEPayload[0].(*message.Encrypted)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received pakcet is not and encrypted payload")
	}
	decryptedIKEPayload, err := decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	eapReqGlobal, ok = decryptedIKEPayload[0].(*message.EAP)
	pingLog.Infof("EAPREQ: %d, %p", eapReqGlobal.Code, eapReqGlobal.Identifier)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received packet is not an EAP payload")
	}
	eapExpanded, ok := eapReqGlobal.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received packet is not an EAP expended payload")
	}

	nasData := eapExpanded.VendorData[4:]
	rec.paketCounter++
	return nasData
}
func InitialRegistrationProcedure(ueContext *ue_context.UEContext, rec *Record) {
	defer measureTime("5G-AKA time", rec)()
	authStarted("Auth_started_counter")
	err, ikeMessage, ok, ikeMessageData, buffer,
		n, ikePayload, encryptedPayload, decryptedIKEPayload, eapVendorTypeData, _,
		nasLength, eapExpanded, eap, _, decodedNAS := initialIkeandNGAP(ueContext, rec)

	// Decode NAS - Authentication Request
	nasData := eapExpanded.VendorData[4:]
	decodedNAS = new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		pingLog.Fatal(err)
	}

	// Calculate for RES*
	//assert.NotNil(t, decodedNAS)
	rand := decodedNAS.AuthenticationRequest.GetRANDValue()
	//TODO here is the snName. if the snName is different to the one sind in InitialRequest. THere will be a mac faiil
	pingLog.Infoln("AUTH RES STAR")
	resStat := ueGlobal.DeriveRESstarAndSetKey(ueGlobal.AuthenticationSubs, rand[:], "5G:mnc001.mcc001.3gppnetwork.org")
	pingLog.Infof("RESSTAT : %d", resStat)
	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")

	// IKE_AUTH - EAP exchange
	ikeMessage = message.BuildIKEHeader(123123, ikeSecurityAssociationGlobal.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 3)

	ikePayload = []message.IKEPayloadType{}

	// EAP-5G vendor type data
	eapVendorTypeData = make([]byte, 4)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// NAS - Authentication Response
	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, pdu...)

	eapExpanded = message.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)
	eap = message.BuildEAP(message.EAPCodeResponse, eapReqGlobal.Identifier, eapExpanded)

	ikePayload = append(ikePayload, eap)

	err = encryptProcedure(ikeSecurityAssociationGlobal, ikePayload, ikeMessage)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}

	// Send to N3IWF
	ikeMessageData, err = message.Encode(ikeMessage)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	_, err = udpConnectionGlobal.WriteToUDP(ikeMessageData, n3iwfUDPAddrGlobal)
	rec.startTime = time.Now()
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	rec.paketCounter++
	// Receive N3IWF reply
	n, _, err = udpConnectionGlobal.ReadFromUDP(buffer)
	rec.addToRtt(time.Since(rec.startTime))
	rec.paketCounter++
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	ikeMessage, err = message.Decode(buffer[:n])
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	encryptedPayload, ok = ikeMessage.IKEPayload[0].(*message.Encrypted)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received pakcet is not and encrypted payload")
	}
	decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociationGlobal, ikeMessage, encryptedPayload)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	eapReqGlobal, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received packet is not an EAP payload")
	}
	eapExpanded, ok = eapReqGlobal.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received packet is not an EAP expended payload")
	}
	if eapReqGlobal.Code != message.EAPCodeFailure {
		pingLog.Info(" --------------------- AUthentication done -----------------------------")
		//syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}

	/*
		pdu = nasTestpacket.GetSecurityModeReject(5)

		// IKE_AUTH - EAP exchange
		ikeMessage = message.BuildIKEHeader(123123, ikeSecurityAssociationGlobal.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 3)

		ikePayload = []message.IKEPayloadType{}

		// EAP-5G vendor type data
		eapVendorTypeData = make([]byte, 4)
		eapVendorTypeData[0] = message.EAP5GType5GNAS

		// NAS - Authentication Response
		nasLength = make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, pdu...)

		eapExpanded = message.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)
		eap = message.BuildEAP(message.EAPCodeResponse, eapReqGlobal.Identifier, eapExpanded)

		ikePayload = append(ikePayload, eap)

		err = encryptProcedure(ikeSecurityAssociationGlobal, ikePayload, ikeMessage)
		if err != nil {
			pingLog.Fatal(err)
		}

		// Send to N3IWF
		ikeMessageData, err = message.Encode(ikeMessage)
		if err != nil {
			pingLog.Fatal(err)
		}
		_, err = udpConnectionGlobal.WriteToUDP(ikeMessageData, n3iwfUDPAddrGlobal)
		if err != nil {
			pingLog.Fatal(err)
		}
		//read uecontextrelease command - otherwise test fails because next iteration gets this as a message
		n, _, err = udpConnectionGlobal.ReadFromUDP(buffer)
		if err != nil {
			pingLog.Fatal(err)
		}
		ikeMessage, err = message.Decode(buffer[:n])
		if err != nil {
			pingLog.Fatal(err)
		}
		encryptedPayload, ok = ikeMessage.IKEPayload[0].(*message.Encrypted)
		if !ok {
			pingLog.Fatal("Received pakcet is not and encrypted payload")
		}
		decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociationGlobal, ikeMessage, encryptedPayload)
		if err != nil {
			pingLog.Fatal(err)
		}
		eapReqGlobal, ok = decryptedIKEPayload[0].(*message.EAP)
		if !ok {
			pingLog.Fatal("Received packet is not an EAP payload")
		}
		eapExpanded, ok = eapReqGlobal.EAPTypeData[0].(*message.EAPExpanded)
		if !ok {
			pingLog.Fatal("Received packet is not an EAP expended payload")
		}
		//Deregistration accept
		pdu = nasTestpacket.GetDeregistrationAccept()
		// IKE_AUTH - EAP exchange
		ikeMessage = message.BuildIKEHeader(123123, ikeSecurityAssociationGlobal.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 3)

		ikePayload = []message.IKEPayloadType{}

		// EAP-5G vendor type data
		eapVendorTypeData = make([]byte, 4)
		eapVendorTypeData[0] = message.EAP5GType5GNAS

		// NAS - Authentication Response
		nasLength = make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, pdu...)

		eapExpanded = message.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)
		eap = message.BuildEAP(message.EAPCodeResponse, eapReqGlobal.Identifier, eapExpanded)

		ikePayload = append(ikePayload, eap)

		err = encryptProcedure(ikeSecurityAssociationGlobal, ikePayload, ikeMessage)
		if err != nil {
			pingLog.Fatal(err)
		}

		// Send to N3IWF
		ikeMessageData, err = message.Encode(ikeMessage)
		if err != nil {
			pingLog.Fatal(err)
		}
		_, err = udpConnectionGlobal.WriteToUDP(ikeMessageData, n3iwfUDPAddrGlobal)
		if err != nil {
			pingLog.Fatal(err)
		}
		/*
			nasData = eapExpanded.VendorData[4:]

			// Send NAS Security Mode Complete Msg
			registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
				mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
			pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
			pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
			//assert.Nil(t, err)

			// IKE_AUTH - EAP exchange
			ikeMessage = message.BuildIKEHeader(123123, ikeSecurityAssociation.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 4)

			ikePayload = []message.IKEPayloadType{}

			// EAP-5G vendor type data
			eapVendorTypeData = make([]byte, 4)
			eapVendorTypeData[0] = message.EAP5GType5GNAS

			// NAS - Authentication Response
			nasLength = make([]byte, 2)
			binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
			eapVendorTypeData = append(eapVendorTypeData, nasLength...)
			eapVendorTypeData = append(eapVendorTypeData, pdu...)

			eapExpanded = message.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)
			eap = message.BuildEAP(message.EAPCodeResponse, eapReqGlobal.Identifier, eapExpanded)

			ikePayload = append(ikePayload, eap)

			err = encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
			if err != nil {
				pingLog.Fatal(err)
			}

			// Send to N3IWF
			ikeMessageData, err = message.Encode(ikeMessage)
			if err != nil {
				pingLog.Fatal(err)
			}
			_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
			if err != nil {
				pingLog.Fatal(err)
			}
			pingLog.Infoln("NAS Security Mode Complete Msg sent ------------- authentication done ")

			// Receive N3IWF reply
			n, _, err = udpConnection.ReadFromUDP(buffer)
			if err != nil {
				pingLog.Fatal(err)
			}
			ikeMessage, err = message.Decode(buffer[:n])
			if err != nil {
				pingLog.Fatal(err)
			}
			encryptedPayload, ok = ikeMessage.IKEPayload[0].(*message.Encrypted)
			if !ok {
				pingLog.Fatal("Received pakcet is not and encrypted payload")
			}
			decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
			if err != nil {
				pingLog.Fatal(err)
			}
			eapReqGlobal, ok = decryptedIKEPayload[0].(*message.EAP)
			if !ok {
				pingLog.Fatal("Received packet is not an EAP payload")
			}
			pingLog.Infof("eapReqGlobal.Code: %d", eapReqGlobal.Code)

			if eapReqGlobal.Code == message.EAPCodeFailure {
				pingLog.Fatal("Not Success")
			}

			// IKE_AUTH - Authentication
			ikeMessage = message.BuildIKEHeader(123123, ikeSecurityAssociation.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 5)

			ikePayload = []message.IKEPayloadType{}

			// Authentication
			auth := message.BuildAuthentication(message.SharedKeyMesageIntegrityCode, []byte{1, 2, 3})
			ikePayload = append(ikePayload, auth)

			// Configuration Request
			configurationAttribute := message.BuildConfigurationAttribute(message.INTERNAL_IP4_ADDRESS, nil)
			configurationRequest := message.BuildConfiguration(message.CFG_REQUEST, []*message.IndividualConfigurationAttribute{configurationAttribute})
			ikePayload = append(ikePayload, configurationRequest)

			err = encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
			if err != nil {
				pingLog.Fatal(err)
			}

			// Send to N3IWF
			ikeMessageData, err = message.Encode(ikeMessage)
			if err != nil {
				pingLog.Fatal(err)
			}
			_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
			if err != nil {
				pingLog.Fatal(err)
			}

			// Receive N3IWF reply
			n, _, err = udpConnection.ReadFromUDP(buffer)
			if err != nil {
				pingLog.Fatal(err)
			}
			ikeMessage, err = message.Decode(buffer[:n])
			if err != nil {
				pingLog.Fatal(err)
			}
			encryptedPayload, ok = ikeMessage.IKEPayload[0].(*message.Encrypted)
			if !ok {
				pingLog.Fatal("Received pakcet is not and encrypted payload")
			}
			decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
			if err != nil {
				pingLog.Fatal(err)
			}

			// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
			var responseSecurityAssociation *message.SecurityAssociation
			var responseTrafficSelectorInitiator *message.TrafficSelectorInitiator
			var responseTrafficSelectorResponder *message.TrafficSelectorResponder
			var responseConfiguration *message.Configuration
			n3iwfNASAddr := new(net.TCPAddr)
			ueAddr := new(net.IPNet)

			for _, ikePayload := range decryptedIKEPayload {
				switch ikePayload.Type() {
				case message.TypeAUTH:
					pingLog.Infoln("Get Authentication from N3IWF")
				case message.TypeSA:
					responseSecurityAssociation = ikePayload.(*message.SecurityAssociation)
					ikeSecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation
				case message.TypeTSi:
					responseTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
				case message.TypeTSr:
					responseTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
				case message.TypeN:
					notification := ikePayload.(*message.Notification)
					if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
						n3iwfNASAddr.IP = net.IPv4(notification.NotificationData[0], notification.NotificationData[1], notification.NotificationData[2], notification.NotificationData[3])
					}
					if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeNAS_TCP_PORT {
						n3iwfNASAddr.Port = int(binary.BigEndian.Uint16(notification.NotificationData))
					}
				case message.TypeCP:
					responseConfiguration = ikePayload.(*message.Configuration)
					if responseConfiguration.ConfigurationType == message.CFG_REPLY {
						for _, configAttr := range responseConfiguration.ConfigurationAttribute {
							if configAttr.Type == message.INTERNAL_IP4_ADDRESS {
								ueAddr.IP = configAttr.Value
							}
							if configAttr.Type == message.INTERNAL_IP4_NETMASK {
								ueAddr.Mask = configAttr.Value
							}
						}
					}
				}
			}

			childSecurityAssociationContext, err := createIKEChildSecurityAssociation(ikeSecurityAssociation.IKEAuthResponseSA)
			if err != nil {
				pingLog.Fatalf("Create child security association context failed: %+v", err)
				return
			}
			err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContext, net.ParseIP(ueContext.N3IWFIpAddress), ueContext.IKEBindAddress, responseTrafficSelectorInitiator.TrafficSelectors[0], responseTrafficSelectorResponder.TrafficSelectors[0])
			if err != nil {
				pingLog.Fatalf("Parse IP address to child security association failed: %+v", err)
				return
			}
			// Select TCP traffic
			childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP

			if err := generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext); err != nil {
				pingLog.Fatalf("Generate key for child SA failed: %+v", err)
				return
			}

			// Aplly XFRM rules
			if err = applyXFRMRule(true, childSecurityAssociationContext); err != nil {
				pingLog.Fatalf("Applying XFRM rules failed: %+v", err)
				return
			}

			// Get link ipsec0
			links, err := netlink.LinkList()
			if err != nil {
				pingLog.Fatal(err)
			}

			var linkIPSec netlink.Link
			for _, link := range links {
				if link.Attrs() != nil {
					if link.Attrs().Name == "ipsec0" {
						linkIPSec = link
						break
					}
				}
			}
			if linkIPSec == nil {
				pingLog.Fatal("No link named ipsec0")
			}

			linkIPSecAddr := &netlink.Addr{
				IPNet: ueAddr,
			}

			if err := netlink.AddrAdd(linkIPSec, linkIPSecAddr); err != nil {
				pingLog.Fatalf("Set ipsec0 addr failed: %v", err)
			}

			defer func() {
				_ = netlink.AddrDel(linkIPSec, linkIPSecAddr)
				_ = netlink.XfrmPolicyFlush()
				_ = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
			}()

			localTCPAddr := &net.TCPAddr{
				IP: ueAddr.IP,
			}
			tcpConnWithN3IWF, err := net.DialTCP("tcp", localTCPAddr, n3iwfNASAddr)
			if err != nil {
				pingLog.Fatal(err)
			}

			nasMsg := make([]byte, 65535)

			_, err = tcpConnWithN3IWF.Read(nasMsg)
			if err != nil {
				pingLog.Fatal(err)
			}

			// send NAS Registration Complete Msg
			pdu = nasTestpacket.GetRegistrationComplete(nil)
			pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
			if err != nil {
				pingLog.Fatal(err)
			}
			_, err = tcpConnWithN3IWF.Write(pdu)
			if err != nil {
				pingLog.Fatal(err)
			}

			time.Sleep(500 * time.Millisecond)

			// UE request PDU session setup
			sNssai := models.Snssai{
				Sst: 1,
				Sd:  "010203",
			}
			pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
			pdu, err = EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
			if err != nil {
				pingLog.Fatal(err)
			}
			_, err = tcpConnWithN3IWF.Write(pdu)
			if err != nil {
				pingLog.Fatal(err)
			}

			// Receive N3IWF reply
			n, _, err = udpConnection.ReadFromUDP(buffer)
			if err != nil {
				pingLog.Fatal(err)
			}
			ikeMessage, err = message.Decode(buffer[:n])
			if err != nil {
				pingLog.Fatal(err)
			}
			pingLog.Infof("IKE message exchange type: %d", ikeMessage.ExchangeType)
			pingLog.Infof("IKE message ID: %d", ikeMessage.MessageID)
			encryptedPayload, ok = ikeMessage.IKEPayload[0].(*message.Encrypted)
			if !ok {
				pingLog.Fatal("Received pakcet is not and encrypted payload")
			}
			decryptedIKEPayload, err = decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
			if err != nil {
				pingLog.Fatal(err)
			}

			var upIPAddr net.IP
			for _, ikePayload := range decryptedIKEPayload {
				switch ikePayload.Type() {
				case message.TypeSA:
					responseSecurityAssociation = ikePayload.(*message.SecurityAssociation)
				case message.TypeTSi:
					responseTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
				case message.TypeTSr:
					responseTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
				case message.TypeN:
					notification := ikePayload.(*message.Notification)
					if notification.NotifyMessageType == message.Vendor3GPPNotifyType5G_QOS_INFO {
						pingLog.Infoln("Received Qos Flow settings")
					}
					if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
						pingLog.Infof("UP IP Address: %+v\n", notification.NotificationData)
						upIPAddr = notification.NotificationData[:4]
					}
				case message.TypeNiNr:
					responseNonce := ikePayload.(*message.Nonce)
					ikeSecurityAssociation.ConcatenatedNonce = responseNonce.NonceData
				}
			}

			// IKE CREATE_CHILD_SA response
			ikeMessage = message.BuildIKEHeader(ikeMessage.InitiatorSPI, ikeMessage.ResponderSPI, message.CREATE_CHILD_SA, message.ResponseBitCheck, ikeMessage.MessageID)

			ikePayload = []message.IKEPayloadType{}

			// SA
			ikePayload = append(ikePayload, responseSecurityAssociation)

			// TSi
			ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

			// TSr
			ikePayload = append(ikePayload, responseTrafficSelectorResponder)

			// Nonce
			localNonce = handler.GenerateRandomNumber().Bytes()
			ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, localNonce...)
			nonce = message.BuildNonce(localNonce)
			ikePayload = append(ikePayload, nonce)

			if err := encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
				pingLog.Fatal(err)
			}

			// Send to N3IWF
			ikeMessageData, err = message.Encode(ikeMessage)
			if err != nil {
				pingLog.Fatal(err)
			}
			_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
			if err != nil {
				pingLog.Fatal(err)
			}

			childSecurityAssociationContextUserPlane, err := createIKEChildSecurityAssociation(responseSecurityAssociation)
			if err != nil {
				pingLog.Fatalf("Create child security association context failed: %+v", err)
				return
			}
			err = parseIPAddressInformationToChildSecurityAssociation(childSecurityAssociationContextUserPlane, net.ParseIP(ueContext.N3IWFIpAddress), ueContext.IKEBindAddress, responseTrafficSelectorResponder.TrafficSelectors[0], responseTrafficSelectorInitiator.TrafficSelectors[0])
			if err != nil {
				pingLog.Fatalf("Parse IP address to child security association failed: %+v", err)
				return
			}
			// Select GRE traffic
			childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE

			if err := generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContextUserPlane); err != nil {
				pingLog.Fatalf("Generate key for child SA failed: %+v", err)
				return
			}

			pingLog.Infof("State function: encr: %d, auth: %d", childSecurityAssociationContextUserPlane.EncryptionAlgorithm, childSecurityAssociationContextUserPlane.IntegrityAlgorithm)
			// Aplly XFRM rules
			if err = applyXFRMRule(false, childSecurityAssociationContextUserPlane); err != nil {
				pingLog.Fatalf("Applying XFRM rules failed: %+v", err)
				return
			}

			// New GRE tunnel interface
			newGRETunnel := &netlink.Gretun{
				LinkAttrs: netlink.LinkAttrs{
					Name: "gretun0",
					MTU:  1400, // #LABORA TODO: investigate why MTU has to be so low
				},
				Local:  ueAddr.IP,
				Remote: upIPAddr,
			}
			if err := netlink.LinkAdd(newGRETunnel); err != nil {
				pingLog.Fatal(err)
			}
			// Get link info
			links, err = netlink.LinkList()
			if err != nil {
				pingLog.Fatal(err)
			}
			var linkGRE netlink.Link
			for _, link := range links {
				if link.Attrs() != nil {
					if link.Attrs().Name == "gretun0" {
						linkGRE = link
						break
					}
				}
			}
			if linkGRE == nil {
				pingLog.Fatal("No link named gretun0")
			}
			// Link address 60.60.0.1/24
			linkGREAddr := &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.IPv4(60, 60, 0, 1),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
			}
			if err := netlink.AddrAdd(linkGRE, linkGREAddr); err != nil {
				pingLog.Fatal(err)
			}
			// Set GRE interface up
			if err := netlink.LinkSetUp(linkGRE); err != nil {
				pingLog.Fatal(err)
			}
			// Add route
			upRoute := &netlink.Route{
				LinkIndex: linkGRE.Attrs().Index,
				Dst: &net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
			}
			if err := netlink.RouteAdd(upRoute); err != nil {
				pingLog.Fatal(err)
			}

			defer func() {
				_ = netlink.LinkSetDown(linkGRE)
				_ = netlink.LinkDel(linkGRE)
			}()

			// Ping remote
			pinger, err := ping.NewPinger("60.60.0.101")
			if err != nil {
				pingLog.Fatal(err)
			}

			// Run with root
			pinger.SetPrivileged(true)

			pinger.OnRecv = func(pkt *ping.Packet) {
				pingLog.Infof("%d bytes from %s: icmp_seq=%d time=%v\n",
					pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
			}
			pinger.OnFinish = func(stats *ping.Statistics) {
				pingLog.Infof("\n--- %s ping statistics ---\n", stats.Addr)
				pingLog.Infof("%d packets transmitted, %d packets received, %v%% packet loss\n",
					stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
				pingLog.Infof("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
					stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
			}

			pinger.Count = 5
			pinger.Timeout = 10 * time.Second
			pinger.Source = "60.60.0.1"

			time.Sleep(3 * time.Second)

			pinger.Run()

			time.Sleep(1 * time.Second)

			stats := pinger.Statistics()
			if stats.PacketsSent != stats.PacketsRecv {
				pingLog.Fatal("Ping Failed")
			} else {
				pingLog.Infoln("Ping Succeed")
			}

			pingLog.Infoln("Keep proccess active for 5 hours...")
			time.Sleep(5 * time.Hour)
	*/

}

func handshake(resp *nasMessage.AuthenticationResponse, udpConnection *net.UDPConn,
	ikeSecurityAssociation *context.IKESecurityAssociation, n3iwfUDPAddr *net.UDPAddr, ikeMessageID *uint32, rec *Record) byte {

	//Write ServerHello first fragment to bearssl
	i := 0
	var eapID byte = 5
	var tlsIncBuffer []byte
	var tlsOutBuffer [5][]byte
	var outFragmented bool
	var currentFragment int
	var fragmentCount int
	var inTLSMessageLength int = 0
	outTLSMessageLength := 0
	var fragmented bool
	for true {
		done, err := Handshake_done()
		if err != nil {
			rec.errors++
			pingLog.Printf("handshake done error")
		}
		if done {
			pingLog.Println("Handshake done")
			return eapID
		} else {
			pingLog.Println("Handshake not done yet")
		}
		state := CheckEngineState()
		pingLog.Infof("Chekd engine state %d", state)
		if state == 1 {
			rec.errors++
			pingLog.Fatalf(" ENGINE ERROR ... CODE: %d", GetLastErroCode())
		}
		var tlsRec [5][]byte
		pingLog.Info("Waiting for reply ....")
		nasData := replayN3IWF(udpConnection, ikeSecurityAssociation, rec)
		pingLog.Info("Reply received")
		rec.addToRtt(time.Since(rec.startTime))
		decodedNAS := new(nas.Message)
		if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
			rec.errors++
			pingLog.Fatal(err)
		}

		eapMessage := decodedNAS.AuthenticationRequest.GetEAPMessage()
		pingLog.Infof("eapMessage TLS Handshake length: %d", len(eapMessage))
		if eapMessage != nil {
			eapID = eapMessage[1]
		}
		pingLog.Infof("eapID : %d", eapID)
		//TODO check if fragmented
		//If there are still tls fragments to send do this first. Expect a EAP/EAP-TLS Response with no data as ack
		if outFragmented {
			if eapMessage != nil {
				//TODO error
			}
			var tlsRecord []byte
			if fitInOneMessage(&tlsOutBuffer, currentFragment, fragmentCount) {
				for ; currentFragment < fragmentCount; currentFragment++ {
					tlsRecord = append(tlsRecord, tlsOutBuffer[currentFragment]...)
				}
			} else {
				tlsRecord = tlsOutBuffer[currentFragment]
				currentFragment++
			}
			var flag uint8 = 0
			if currentFragment < fragmentCount-1 {
				flag |= (1 << 6)
			}
			eapMessageOut := createEAPMessageFlag(tlsOutBuffer[currentFragment], eapID, flag, 0)
			pingLog.Printf("------------------ EAP ID IN MESsAGE: %d", eapID)
			pingLog.Printf("SSL enginge state after Reading from bearSSL %d", CheckEngineState())
			resp.EAPMessage = &eapMessageOut
			buffer := new(bytes.Buffer)
			resp.EncodeAuthenticationResponse(buffer)
			writeToN3IWF(ikeSecurityAssociation, buffer, udpConnection, n3iwfUDPAddr, *ikeMessageID, rec)
			rec.startTime = time.Now()
			*ikeMessageID++
			pingLog.Printf("Curretn FRAGMENT: %d || FRAGMENTCOUNT: %s", currentFragment, fragmentCount)

			if currentFragment == fragmentCount {
				outFragmented = false
			}
			continue

		}

		eapHeader := eapMessage[0:6]
		pingLog.Printf("EAP HEADER: %d", eapHeader)
		//if first bit is set the length included
		if eapHeader[5]&(1<<7) > 0 {
			pingLog.Println("------------------------------Length flag set -----------------------------------------")
			inTLSMessageLength = int(binary.BigEndian.Uint32(eapMessage[6:10]))
			tlsIncBuffer = eapMessage[10:]
			fragmented = true
		} else {
			tlsIncBuffer = eapMessage[6:]
		}
		state = CheckEngineState()
		if state == 4 {
			// write data to bearssl
			pingLog.Printf("Counter : %d", i)
			i++
			tlsM := tlsIncBuffer
			pingLog.Printf("TLS MEssage length to bearssl; %d", len(tlsM))
			WriteToServer(tlsM)
			rec.startTime = time.Now()
			pingLog.Printf("After wrting enginge state", CheckEngineState())
		}
		state = CheckEngineState()
		pingLog.Printf("current state", state)
		if state == 2 {
			pingLog.Printf("Counter : %d", i)
			i++
			//read from bearssl and send this data
			tlsRec, outTLSMessageLength, fragmentCount, err = ReadFromServer()
			pingLog.Printf("TLSREC len: ", len(tlsRec[0]))
			//if true fragmentation needed
			var eapMessageOut nasType.EAPMessage
			if outTLSMessageLength > 1495 {
				tlsOutBuffer = tlsRec
				outFragmented = true
				currentFragment = 0
				pingLog.Printf("-------------------------- FRAGMENT COUNT; %d ----------------------------", fragmentCount)
				//for i, r := range tlsRec {
				//	pingLog.Printf("tlsRec fragment: %d, %x", i, r)
				//	pingLog.Printf("len of fragment: %d", len(r))
				//}
				var flag uint8 = 0
				flag |= (1 << 7)
				flag |= (1 << 6)
				eapMessageOut = createEAPMessageFlag(tlsOutBuffer[currentFragment], eapID, flag, uint32(outTLSMessageLength))
				currentFragment++
			} else {
				eapMessageOut = createEAPMessage(tlsRec, eapID)
			}

			pingLog.Printf("SSL enginge state after Reading from bearSSL %d", CheckEngineState())
			resp.EAPMessage = &eapMessageOut
			buffer := new(bytes.Buffer)
			resp.EncodeAuthenticationResponse(buffer)
			writeToN3IWF(ikeSecurityAssociation, buffer, udpConnection, n3iwfUDPAddr, *ikeMessageID, rec)
			rec.startTime = time.Now()
			*ikeMessageID++
		}

		if eapHeader[5]&(1<<6) > 0 {
			pingLog.Println("------------------------------Fragment flag set -----------------------------------------")
			eapMessageOut := createEAPACK(eapHeader[1])
			pingLog.Infof("EAP ACK: %d", eapMessageOut)
			resp.EAPMessage = &eapMessageOut
			buffer := new(bytes.Buffer)
			resp.EncodeAuthenticationResponse(buffer)
			err = writeToN3IWF(ikeSecurityAssociation, buffer, udpConnection, n3iwfUDPAddr, *ikeMessageID, rec)
			rec.startTime = time.Now()
			*ikeMessageID++
		} else {
			if fragmented {
				if inTLSMessageLength > 0 {
					tlsLen := len(tlsIncBuffer)
					if tlsLen != inTLSMessageLength {
						//TODO send eap failure
					}
					fragmented = false
					inTLSMessageLength = 0
				}
			}
		}
		if state == 8 {
			//handshake done
			pingLog.Print("Handshake done")
			return eapID
		}
		if state != 8 && state != 2 && state != 4 {
			pingLog.Printf("Engine fail: %d", state)
			code := GetLastErroCode()
			pingLog.Fatalf("Error code: %d", code)
			return 0
		}
	}
	return 0
}

func fitInOneMessage(i *[5][]byte, fragment int, count int) bool {
	sum := 0
	for ; fragment < count; fragment++ {
		sum += len(i[fragment])
	}
	if sum < 1495 {
		return true
	} else {
		return false
	}
}

func createEAPACK(eapID byte) nasType.EAPMessage {
	eapData := []byte{2, eapID, 0, 6, 13, 0}
	eapMessage := nasType.EAPMessage{Iei: 120, Len: uint16(len(eapData)), Buffer: eapData} //IE is 78 (TS 124501 8.2.2.1.1) and (9.11.2.2)
	return eapMessage
}

func createEAPMessageFlag(data []byte, eapID byte, flag uint8, tlsMessageLength uint32) nasType.EAPMessage {
	opts := gopacket.SerializeOptions{}
	length := uint16(len(data)) + 6
	if tlsMessageLength != 0 {
		length += 4
	}
	log.Printf("EAP MESSAGE WITH FLAG LEN: %d", length)
	eap := &EAPTLS{
		Code:             2,
		Id:               eapID,
		Length:           length, // eigentlich 6 uint16(EAP_TLS_HEADER_LENGTH)
		Type:             13,
		Flags:            flag,
		TLSMessageLength: tlsMessageLength,
		TypeData:         data,
	}
	eapBuf := gopacket.NewSerializeBuffer()
	err := eap.SerializeTo(eapBuf, opts)
	if err != nil {
		panic(err)
	}
	eapData := eapBuf.Bytes()
	//eapData = append(eapData, typeData[len(typeData)-1])
	//log.Printf("EAP DATA : %d", eapData)
	//log.Printf("TLS DATA : %d", data)
	eapLen := len(eapData)
	log.Printf("EAPDATA WITH FLAG  LEN: %d", eapLen)
	log.Printf("EAPDATA WITH FLAG  uint16LEN: %d", uint16(eapLen))
	//IE is 78 (TS 124501 8.2.2.1.1) and (9.11.2.2)
	eapMessage := nasType.EAPMessage{Iei: 120, Len: uint16(eapLen), Buffer: eapData}
	return eapMessage
}

func createEAPMessage(data [5][]byte, eapID byte) nasType.EAPMessage {
	opts := gopacket.SerializeOptions{}
	typeData := data[0]
	tlsLen := len(data[0])
	for i := 1; i < len(data); i++ {
		if data[i] != nil {
			typeData = append(typeData, data[i]...)
			tlsLen += len(data[i])
		} else {
			break
		}
	}

	eap := &EAPTLS{
		Code:     2,
		Id:       eapID,
		Length:   uint16(tlsLen) + 6, // eigentlich 6 uint16(EAP_TLS_HEADER_LENGTH)
		Type:     13,
		Flags:    0,
		TypeData: typeData,
	}
	eapBuf := gopacket.NewSerializeBuffer()
	err := eap.SerializeTo(eapBuf, opts)
	if err != nil {
		panic(err)
	}
	eapData := eapBuf.Bytes()
	eapData = append(eapData, typeData[len(typeData)-1])
	//log.Printf("EAP DATA : %d", eapData)
	//log.Printf("TLS DATA : %d", typeData)
	eapLen := len(eapData)
	eapMessage := nasType.EAPMessage{Iei: 120, Len: uint16(eapLen) - 1, Buffer: eapData} //IE is 78 (TS 124501 8.2.2.1.1) and (9.11.2.2)
	return eapMessage
}

func initialIkeandNGAP(ueContext *ue_context.UEContext, rec *Record) (error, *message.IKEMessage, bool, []byte, []byte, int, []message.IKEPayloadType, *message.Encrypted, []message.IKEPayloadType, []byte, *nasType.UESecurityCapability, []byte, *message.EAPExpanded, *message.EAP, *message.EAP, *nas.Message) {
	//if !ueContext.IKETunnelActive {
	ikeInit(ueContext)
	//}

	// IKE_AUTH - EAP exchange
	ikeMessage := message.BuildIKEHeader(123123, ikeSecurityAssociationGlobal.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 2)

	ikePayload := []message.IKEPayloadType{}

	// EAP-5G vendor type data
	eapVendorTypeData := make([]byte, 2)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// AN Parameters
	anParameters := buildEAP5GANParameters()
	anParametersLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)

	// NAS
	ueSecurityCapability := ueGlobal.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GSGlobal, nil, ueSecurityCapability, nil, nil, nil)

	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

	eapExpanded := message.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)
	eap := message.BuildEAP(message.EAPCodeResponse, eapIdentifierGlobal, eapExpanded)

	ikePayload = append(ikePayload, eap)

	if err := encryptProcedure(ikeSecurityAssociationGlobal, ikePayload, ikeMessage); err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}

	// Send to N3IWF
	ikeMessageData, err := message.Encode(ikeMessage)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)

	}
	if _, err := udpConnectionGlobal.WriteToUDP(ikeMessageData, n3iwfUDPAddrGlobal); err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	rec.startTime = time.Now()
	rec.paketCounter++
	// Receive N3IWF reply
	buffer := make([]byte, 65535)
	n, _, err := udpConnectionGlobal.ReadFromUDP(buffer)
	rec.addToRtt(time.Since(rec.startTime))
	rec.paketCounter++
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	ikeMessage, err = message.Decode(buffer[:n])
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal(err)
	}
	encryptedPayload, ok := ikeMessage.IKEPayload[0].(*message.Encrypted)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received payload is not an encrypted payload")
	}
	decryptedIKEPayload, err := decryptProcedure(ikeSecurityAssociationGlobal, ikeMessage, encryptedPayload)
	if err != nil {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatalf("Decrypt IKE message failed: %+v", err)
	}

	eapReqGlobal, ok = decryptedIKEPayload[0].(*message.EAP)
	//pingLog.Infof("decryptedData line 1723: %d, %p", eapReqGlobal.Code, eapReqGlobal.EAPTypeData)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("Received packet is not an EAP payload")
	}

	var decodedNAS *nas.Message

	eapExpanded, ok = eapReqGlobal.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		rec.errors++
		rec.errorReason = err.Error()
		rec.WriteToCSV(rec.filename)
		pingLog.Fatal("The EAP data is not an EAP expended.")
	}
	return err, ikeMessage, ok, ikeMessageData, buffer, n, ikePayload, encryptedPayload, decryptedIKEPayload, eapVendorTypeData, ueSecurityCapability, nasLength, eapExpanded, eap, eapReqGlobal, decodedNAS
}

func initialUEAttack(ueContext *ue_context.UEContext, rec *Record) {
	ikeInit(ueContext)

	// IKE_AUTH - EAP exchange
	ikeMessage := message.BuildIKEHeader(123123, ikeSecurityAssociationGlobal.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 2)

	ikePayload := []message.IKEPayloadType{}

	// EAP-5G vendor type data
	eapVendorTypeData := make([]byte, 2)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// AN Parameters
	anParameters := buildEAP5GANParameters()
	anParametersLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)

	// NAS
	ueSecurityCapability := ueGlobal.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GSGlobal, nil, ueSecurityCapability, nil, nil, nil)

	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

	eapExpanded := message.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)
	eap := message.BuildEAP(message.EAPCodeResponse, eapIdentifierGlobal, eapExpanded)

	ikePayload = append(ikePayload, eap)

	if err := encryptProcedure(ikeSecurityAssociationGlobal, ikePayload, ikeMessage); err != nil {
		pingLog.Fatal(err)
	}

	// Send to N3IWF
	for i := 0; i < 100; i++ {
		ikeMessageData, err := message.Encode(ikeMessage)
		if err != nil {
			pingLog.Fatal(err)
		}
		if _, err := udpConnectionGlobal.WriteToUDP(ikeMessageData, n3iwfUDPAddrGlobal); err != nil {
			pingLog.Fatal(err)
		}
		time.Sleep(500)
	}
}

func ikeInit(ueContext *ue_context.UEContext) {
	// New UE
	ue := NewUeRanContext(fmt.Sprintf("imsi-%s", ueContext.SUPIorSUCI), 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	//ue := NewUeRanContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = 1
	// auth data here
	ue.AuthenticationSubs = ueContext.GetAuthSubscriptionOpen5G()
	/*
		mobileIdentity5GS := nasType.MobileIdentity5GS{
			Len:    12, // suci
			Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		}

	*/
	pingLog.Infof("SUPI : ")
	var mobileIdentity5GS nasType.MobileIdentity5GS
	if ueContext.AuthenticationMethod == models.AuthMethod__5_G_AKA {
		if ueContext.SUPIorSUCI == "001010000000001" {
			mobileIdentity5GS = mobileIdentityAKA1
		} else if ueContext.SUPIorSUCI == "001010000000011" {
			mobileIdentity5GS = mobileIdentityAKA2
		} else if ueContext.SUPIorSUCI == "001010000001101" {
			mobileIdentity5GS = mobileIdentityAKA3
		} else if ueContext.SUPIorSUCI == "001010000011101" {
			mobileIdentity5GS = mobileIdentityAKA4
		} else if ueContext.SUPIorSUCI == "001010000011111" {
			mobileIdentity5GS = mobileIdentityAKA5
		} else if ueContext.SUPIorSUCI == "001010000011110" {
			mobileIdentity5GS = mobileIdentityAKA6
		} else if ueContext.SUPIorSUCI == "001010000011100" {
			mobileIdentity5GS = mobileIdentityAKA7
		} else if ueContext.SUPIorSUCI == "001010000011000" {
			mobileIdentity5GS = mobileIdentityAKA8
		} else if ueContext.SUPIorSUCI == "001010000010000" {
			mobileIdentity5GS = mobileIdentityAKA9
		} else if ueContext.SUPIorSUCI == "001010000101000" {
			mobileIdentity5GS = mobileIdentityAKA10
		} else {
			pingLog.Fatal("SUCI WRONG TO 5G AKA")
		}

	} else {
		if ueContext.SUPIorSUCI == "0100f110000000000000000110" {
			mobileIdentity5GS = mobileIdentityTLS1
			pingLog.Info("mobileIdentityTLS1 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000000010110" {
			mobileIdentity5GS = mobileIdentityTLS2
			pingLog.Info("mobileIdentityTLS2 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000001010110" {
			mobileIdentity5GS = mobileIdentityTLS3
			pingLog.Info("mobileIdentityTLS3 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000101010110" {
			mobileIdentity5GS = mobileIdentityTLS4
			pingLog.Info("mobileIdentityTLS4 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000001101010110" {
			mobileIdentity5GS = mobileIdentityTLS5
			pingLog.Info("mobileIdentityTLS5 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000000110110" {
			mobileIdentity5GS = mobileIdentityTLS6
			pingLog.Info("mobileIdentityTLS6 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000001110110" {
			mobileIdentity5GS = mobileIdentityTLS7
			pingLog.Info("mobileIdentityTLS7 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000011110110" {
			mobileIdentity5GS = mobileIdentityTLS8
			pingLog.Info("mobileIdentityTLS8 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000111110110" {
			mobileIdentity5GS = mobileIdentityTLS9
			pingLog.Info("mobileIdentityTLS9 used")
		} else if ueContext.SUPIorSUCI == "0100f110000000000110110110" {
			mobileIdentity5GS = mobileIdentityTLS10
			pingLog.Info("mobileIdentityTLS10 used")
		} else {
			pingLog.Fatal("SUCI WRONG TO EAP TLS")
		}
	}

	n3iwfUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:500", ueContext.N3IWFIpAddress))
	if err != nil {
		pingLog.Fatal(err)
	}

	udpConnection := setupUDPSocket(ueContext, pingLog)

	// IKE_SA_INIT
	ikeMessage := message.BuildIKEHeader(123123, 0, message.IKE_SA_INIT, message.InitiatorBitCheck, 0)

	// Security Association
	proposal := message.BuildProposal(1, message.TypeIKE, nil)
	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256
	encryptTransform := message.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	message.AppendTransformToProposal(proposal, encryptTransform)
	integrityTransform := message.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	message.AppendTransformToProposal(proposal, integrityTransform)
	pseudorandomFunctionTransform := message.BuildTransform(message.TypePseudorandomFunction, message.PRF_HMAC_SHA1, nil, nil, nil)
	message.AppendTransformToProposal(proposal, pseudorandomFunctionTransform)
	diffiehellmanTransform := message.BuildTransform(message.TypeDiffieHellmanGroup, message.DH_2048_BIT_MODP, nil, nil, nil)
	message.AppendTransformToProposal(proposal, diffiehellmanTransform)
	securityAssociation := message.BuildSecurityAssociation([]*message.Proposal{proposal})
	ikeMessage.IKEPayload = append(ikeMessage.IKEPayload, securityAssociation)

	// Key exchange data
	generator := new(big.Int).SetUint64(handler.Group14Generator)
	factor, ok := new(big.Int).SetString(handler.Group14PrimeString, 16)
	if !ok {
		pingLog.Fatal("Generate key exchange datd failed")
	}
	secert := handler.GenerateRandomNumber()
	localPublicKeyExchangeValue := new(big.Int).Exp(generator, secert, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	keyExchangeData := message.BUildKeyExchange(message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)
	ikeMessage.IKEPayload = append(ikeMessage.IKEPayload, keyExchangeData)

	// Nonce
	localNonce := handler.GenerateRandomNumber().Bytes()
	nonce := message.BuildNonce(localNonce)
	ikeMessage.IKEPayload = append(ikeMessage.IKEPayload, nonce)

	// Send to N3IWF
	ikeMessageData, err := message.Encode(ikeMessage)
	if err != nil {
		pingLog.Fatal(err)
	}
	pingLog.Infof("ip and port : %d", n3iwfUDPAddr)
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		pingLog.Fatal(err)
	}
	pingLog.Info("test1")
	// Receive N3IWF reply
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
	if err != nil {
		pingLog.Fatal(err)
	}
	pingLog.Info("test2")
	ikeMessage, err = message.Decode(buffer[:n])
	if err != nil {
		pingLog.Fatal(err)
	}

	var sharedKeyExchangeData []byte
	var remoteNonce []byte

	for _, ikePayload := range ikeMessage.IKEPayload {
		switch ikePayload.Type() {
		case message.TypeSA:
			pingLog.Infoln("Get SA payload")
		case message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secert, factor).Bytes()
		case message.TypeNiNr:
			remoteNonce = ikePayload.(*message.Nonce).NonceData
		}
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               123123,
		RemoteSPI:              ikeMessage.ResponderSPI,
		EncryptionAlgorithm:    encryptTransform,
		IntegrityAlgorithm:     integrityTransform,
		PseudorandomFunction:   pseudorandomFunctionTransform,
		DiffieHellmanGroup:     diffiehellmanTransform,
		ConcatenatedNonce:      append(localNonce, remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyExchangeData,
	}

	if err := generateKeyForIKESA(ikeSecurityAssociation); err != nil {
		pingLog.Fatalf("Generate key for IKE SA failed: %+v", err)
	}

	// IKE_AUTH
	ikeMessage = message.BuildIKEHeader(123123, ikeSecurityAssociation.RemoteSPI, message.IKE_AUTH, message.InitiatorBitCheck, 1)

	var ikePayload []message.IKEPayloadType

	// Identification
	identification := message.BuildIdentificationInitiator(message.ID_FQDN, []byte("UE"))
	ikePayload = append(ikePayload, identification)

	// Security Association
	proposal = message.BuildProposal(1, message.TypeESP, []byte{0, 0, 0, 1})
	encryptTransform = message.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	message.AppendTransformToProposal(proposal, encryptTransform)
	integrityTransform = message.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	message.AppendTransformToProposal(proposal, integrityTransform)
	extendedSequenceNumbersTransform := message.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_NO, nil, nil, nil)
	message.AppendTransformToProposal(proposal, extendedSequenceNumbersTransform)
	securityAssociation = message.BuildSecurityAssociation([]*message.Proposal{proposal})
	ikePayload = append(ikePayload, securityAssociation)

	// Traffic Selector
	inidividualTrafficSelector := message.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	trafficSelectorInitiator := message.BuildTrafficSelectorInitiator([]*message.IndividualTrafficSelector{inidividualTrafficSelector})
	ikePayload = append(ikePayload, trafficSelectorInitiator)
	trafficSelectorResponder := message.BuildTrafficSelectorResponder([]*message.IndividualTrafficSelector{inidividualTrafficSelector})
	ikePayload = append(ikePayload, trafficSelectorResponder)

	if err := encryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		pingLog.Fatalf("Encrypting IKE message failed: %+v", err)
	}

	// Send to N3IWF
	ikeMessageData, err = message.Encode(ikeMessage)
	if err != nil {
		pingLog.Fatal(err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		pingLog.Fatal(err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		pingLog.Fatal(err)
	}
	ikeMessage, err = message.Decode(buffer[:n])
	if err != nil {
		pingLog.Fatal(err)
	}

	encryptedPayload, ok := ikeMessage.IKEPayload[0].(*message.Encrypted)
	if !ok {
		pingLog.Fatal("Received payload is not an encrypted payload")
	}

	decryptedIKEPayload, err := decryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		pingLog.Fatalf("Decrypt IKE message failed: %+v", err)
	}

	var eapIdentifier uint8

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeIDr:
			pingLog.Infoln("Get IDr")
		case message.TypeAUTH:
			pingLog.Infoln("Get AUTH")
		case message.TypeCERT:
			pingLog.Infoln("Get CERT")
		case message.TypeEAP:
			eapIdentifier = ikePayload.(*message.EAP).Identifier
			pingLog.Infoln("Get EAP")
		}
	}
	//IKETunnelActive needed for Tests - see TestTLS100
	ueContext.IKETunnelActive = true
	ueGlobal = ue
	mobileIdentity5GSGlobal = mobileIdentity5GS
	n3iwfUDPAddrGlobal = n3iwfUDPAddr
	udpConnectionGlobal = udpConnection
	localNonceGlobal = localNonce
	nonceGlobal = nonce
	ikeSecurityAssociationGlobal = ikeSecurityAssociation
	eapIdentifierGlobal = eapIdentifier
}

func clientHelloAttack(ueContext *ue_context.UEContext, rec *Record) {
	err, ikeMessage, ok, ikeMessageData, buffer,
		n, ikePayload, encryptedPayload, decryptedIKEPayload, eapVendorTypeData, ueSecurityCapability,
		nasLength, eapExpanded, eap, eapReq, decodedNAS := initialIkeandNGAP(ueContext, rec)
	log.Printf("not used: ", ueGlobal, mobileIdentity5GSGlobal, err, ikeMessage, ok, localNonceGlobal, nonceGlobal, ikeMessageData, buffer,
		n, ikePayload, encryptedPayload, decryptedIKEPayload, eapVendorTypeData, ueSecurityCapability, nasLength, eap)
	// Decode NAS - Authentication Request
	pingLog.Infof("%d", eapReq)
	nasData := eapExpanded.VendorData[4:]
	decodedNAS = new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		pingLog.Fatal(err)
	}

	eapMessage := decodedNAS.AuthenticationRequest.GetEAPMessage()
	pingLog.Infof("eapMessage TLS START: %d", eapMessage)
	eapID := eapMessage[1]
	pingLog.Infof("eapID : %d", eapID)

	resp := nasMessage.NewAuthenticationResponse(1)
	resp.ExtendedProtocolDiscriminator = nasType.ExtendedProtocolDiscriminator{Octet: 126}
	resp.SpareHalfOctetAndSecurityHeaderType = nasType.SpareHalfOctetAndSecurityHeaderType{Octet: 0}
	resp.AuthenticationResponseMessageIdentity = nasType.AuthenticationResponseMessageIdentity{Octet: 87}

	Client()
	engineState := GetEngineState()
	log.Printf("1 SSL enginge state", engineState)
	tlsRec, tlsMessageLength, fragmentsCount, err := ReadFromServer()
	log.Printf("Fragmentcount: ", fragmentsCount)
	log.Printf("TLSMessageLength: ", tlsMessageLength)
	log.Printf("TLSREC len: ", len(tlsRec[0]))
	engineState = GetEngineState()
	log.Printf("2 SSL enginge state", engineState)
	errCode := GetLastErroCode()
	log.Printf(" Last Error code engine", errCode)
	engineState = GetEngineState()
	log.Printf("SSL enginge state", engineState)
	eapMessageOut := createEAPMessage(tlsRec, eapID)
	resp.EAPMessage = &eapMessageOut
	bufferResp := new(bytes.Buffer)
	resp.EncodeAuthenticationResponse(bufferResp)
	var ikeMessageID uint32 = 3
	for ; ikeMessageID < 100; ikeMessageID++ {
		err = writeToN3IWF(ikeSecurityAssociationGlobal, bufferResp, udpConnectionGlobal, n3iwfUDPAddrGlobal, ikeMessageID, rec)
	}

}
func setUESecurityCapability(ue *UeRanContext) (UESecurityCapability *nasType.UESecurityCapability) {
	UESecurityCapability = &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    8,
		Buffer: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	switch ue.CipheringAlg {
	case security.AlgCiphering128NEA0:
		UESecurityCapability.SetEA0_5G(1)
	case security.AlgCiphering128NEA1:
		UESecurityCapability.SetEA1_128_5G(1)
	case security.AlgCiphering128NEA2:
		UESecurityCapability.SetEA2_128_5G(1)
	case security.AlgCiphering128NEA3:
		UESecurityCapability.SetEA3_128_5G(1)
	}

	switch ue.IntegrityAlg {
	case security.AlgIntegrity128NIA0:
		UESecurityCapability.SetIA0_5G(1)
	case security.AlgIntegrity128NIA1:
		UESecurityCapability.SetIA1_128_5G(1)
	case security.AlgIntegrity128NIA2:
		UESecurityCapability.SetIA2_128_5G(1)
	case security.AlgIntegrity128NIA3:
		UESecurityCapability.SetIA3_128_5G(1)
	}

	return
}

func HandleRegistrationProcedure(ueContext *ue_context.UEContext) {

	// TODO: #LABORA what is the current step??
	/*
		if IDLE and DEREGISTERED
			execute Initial Registration Procedure
		elif IDLE and REGISTERED
			execute Service Request
		elif CONNECTED AND DEREGISTERED
			execute Registration Procedure
		else
			execute Registration Procedure
	*/
	if ueContext.AttackVariant == "InitialUE" {
		pingLog.Infof("InitialUE attack")
		var rec Record
		rec.rtts = make([]int64, 1)
		initialUEAttack(ueContext, &rec)
	} else if ueContext.AttackVariant == "ClientHello" {
		pingLog.Infof("ClientHello Attack")
		var rec Record
		rec.rtts = make([]int64, 1)
		clientHelloAttack(ueContext, &rec)
	} else if ueContext.AttackVariant == "TestTLS100" {
		pingLog.Infof("Test TLS 100 times")

		testTLS(ueContext)
	} else if ueContext.AttackVariant == "Test5GAKA100" {
		test5GAKA(ueContext)

	} else {

		pingLog.Infof("AUTH TYPE: %d", ueContext.AuthenticationMethod)
		if ueContext.AuthenticationMethod == models.AuthMethod__5_G_AKA {
			var rec Record
			rec.rtts = make([]int64, 1)
			InitialRegistrationProcedure(ueContext, &rec)
		} else if ueContext.AuthenticationMethod == models.AuthMethod_EAP_TLS {
			var rec Record
			rec.rtts = make([]int64, 1)
			WriteHeader("EAP_TLS_KPI_single")
			InitialRegistrationProcedureTLS(ueContext, &rec)
			rec.WriteToCSV("EAP_TLS_KPI_single")
		} else if ueContext.AuthenticationMethod == models.AuthMethod_EAP_AKA_PRIME {
			pingLog.Fatalf("AUTH METHOD NOT SUPPORTED")
		} else {
			pingLog.Fatalf("AUTH METHOD NOT VALID")
		}
	}

	pingLog.Info(" --------------------- AUthentication/Attack done -----------------------------")
	//syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	os.Exit(0)
}

func test5GAKA(ueContext *ue_context.UEContext) {
	pingLog.Info("Test 5G AKA")
	WriteHeader("5G_AKA_KPI" + time.Now().Format("01_01_2002"))
	//for i := 0; i < 100; i++ {
	var rec Record
	rec.rtts = make([]int64, 1)
	rec.paketCounter = 0
	rec.filename = "5G_AKA_KPI" + time.Now().Format("01_01_2002")
	InitialRegistrationProcedure(ueContext, &rec)
	rec.WriteToCSV("5G_AKA_KPI" + time.Now().Format("01_01_2002"))
	//fmt.Println("Before sleep the time is:", time.Now().Unix()) // Before sleep the time is: 1257894000
	//time.Sleep(5 * time.Second)                                 // pauses execution for 2 seconds
	//fmt.Println("After sleep the time is:", time.Now().Unix())

	//}
}

func testTLS(ueContext *ue_context.UEContext) {

	WriteHeader("EAP_TLS_KPI" + time.Now().Format("01_01_2002"))
	//for i := 0; i < 100; i++ {
	var rec Record
	rec.rtts = make([]int64, 1)
	rec.paketCounter = 0
	rec.errorReason = ""
	rec.filename = "EAP_TLS_KPI" + time.Now().Format("01_01_2002")
	InitialRegistrationProcedureTLS(ueContext, &rec)
	rec.WriteToCSV("EAP_TLS_KPI" + time.Now().Format("01_01_2002"))
	pingLog.Info("sleep ")
	//}
	pingLog.Infof("Test done 100 Times see EAP_TLS_KPI.csv")
}

func HandleDeregistrationProcedure(ueContext *ue_context.UEContext) {

}

func SetupPDUSession(ueContext *ue_context.UEContext) {

}

func DeregistrationProcedure(ueContext *ue_context.UEContext) {

}
