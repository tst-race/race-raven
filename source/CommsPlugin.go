//
// Copyright 2023 Two Six Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// CommsPluginTwoSix Interface. Is a Golang  implementation of the RACE T2 Plugin. Will
// perform obfuscated communication for the RACE system.

package main

import "C"

import (
	"encoding/json"
	"fmt"
	commsShims "shims"
	"strings"
	"sync"
	"time"
	"unsafe"
)


var established_account *account = nil

// A CommsConn represents a logical connection connecting two RACE nodes
type CommsConn interface {
	// Returns the link ID of the connection
	GetLinkId() string
	// Returns the link type of the connection
	GetLinkType() commsShims.LinkType
	// Adds a connection ID to the connection, returning the new number of IDs
	AddConnectionId(connectionId string) int
	// Removes a connection ID from the connection, returning the new number of IDs
	RemoveConnectionId(connectionId string) int
	// Gets the list of connection IDs associated with the connection
	GetConnectionIds() []string
	// Closes the connection
	Close() error
	// Writes the given raw message payload to the connection
	Write(msg []byte) error
	// Starts receiving messages over the connection. This method should block
	// until the connection has been closed. It will be invoked in a goroutine.
	Receive(plugin *overwrittenMethodsOnCommsPluginRacecar)

	GetProfile() unicastProfile
}

// Attributes common to unicast and multicast connection types
type commsConnCommon struct {
	connectionIdsAsMap map[string]bool
	connectionIdsMutex sync.RWMutex
	LinkId             string
	LinkType           commsShims.LinkType
	Profile		   unicastProfile
}

func (conn *commsConnCommon) GetProfile() unicastProfile {
	return conn.Profile
}

// Returns the link ID of the given connection
func (conn *commsConnCommon) GetLinkId() string {
	return conn.LinkId
}

// Returns the link type of the given connection
func (conn *commsConnCommon) GetLinkType() commsShims.LinkType {
	return conn.LinkType
}

// Adds a connection ID to the connection, returning the new number of IDs
func (conn *commsConnCommon) AddConnectionId(connectionId string) int {
	conn.connectionIdsMutex.Lock()
	defer conn.connectionIdsMutex.Unlock()
	if connectionId != "" {
		conn.connectionIdsAsMap[connectionId] = true
	} else {
		logWarning("commsConnCommon::AddConnectionId: invalid connection ID is empty string.")
	}
	return len(conn.connectionIdsAsMap)
}

// Removes a connection ID from the connection, returning the new number of IDs
func (conn *commsConnCommon) RemoveConnectionId(connectionId string) int {
	conn.connectionIdsMutex.Lock()
	defer conn.connectionIdsMutex.Unlock()
	delete(conn.connectionIdsAsMap, connectionId)
	return len(conn.connectionIdsAsMap)
}

// Gets the list of connection IDs associated with the connection
func (conn *commsConnCommon) GetConnectionIds() []string {
	conn.connectionIdsMutex.RLock()
	defer conn.connectionIdsMutex.RUnlock()
	var keys []string
	for key := range conn.connectionIdsAsMap {
		keys = append(keys, key)
	}
	return keys
}

// Unicast/direct connection type
type commsConnRaven struct {
	commsConnCommon
	Account *account
	Rcvrs   []string
	Is_open bool
}

// Unicast/direct connection parameters
type unicastProfile struct {
	Sender		string `json:"sender"`
	Rcvr		string `json:"rcvr"`
}

type email_account struct {
	Address	string `json:"address"`
	EmailServer	string `json:"hostname"`
	Password	string `json:"password"`
	SmtpPort	uint64 `json:"smtp_port"`
	ImapPort	uint64 `json:"imap_port"`
	InsecureTLS	bool   `json:"insecure_TLS"`
}

func initializeAccountStruct(host string, smtpPort uint64, imapPort uint64, uname string, password string, insecure_tls bool, keyringPath string) (*account, error) {
	logPrefix := fmt.Sprintf("InitializeAccountStruct ")
	logDebug(logPrefix, "initializing")
	if established_account != nil {
		// XXX: We should probably do some modifications to accounts
		// ie, maybe a mapping ensuring only one account object per email address, but we could support multiple accounts
		// Should also separate sending from recieving behavior more cleanly
		// XXX: Assumes established account is the same
		// XXX: Assumes a singular account
		return established_account, nil
	}
	logDebug(logPrefix, "new account")
	account, err := newAccount(host, smtpPort, imapPort, uname, password, keyringPath)
	if err != nil {
		logError("failed to initialize account", err.Error())
		return nil, err
	}
	logDebug(logPrefix, "insecure_tls")
	account.insecure_tls = insecure_tls
	
	logDebug(logPrefix, "launch subroutine")
	// start the thing that'll actually send messages
	go ravenPeriodicSender(account)
	
	logDebug(logPrefix, "launched")
	established_account = account
	return account, nil
}

// Creates a new unicast connection instance
func newRavenConn(newConnectionId string, linkType commsShims.LinkType, linkId string, linkProfile string) (CommsConn, error) {
	logDebug("creating a new raven instance with connectionID ", newConnectionId, ", linkId ", linkId, " and linkProfile ", linkProfile)
	var profile unicastProfile
	err := json.Unmarshal([]byte(linkProfile), &profile)
	if err != nil {
		logError("failed to parse link profile json: ", err.Error())
		return nil, err
	}
	logDebug("unmarshalled profile is ", profile)
	if newConnectionId == "" {
		logError("newMulticastConn: invalid connection ID is empty string")
		return nil, err
	}
	logDebug("profile.uname is ", profile.Sender, "; linkProfile is -->", linkProfile)
	account := established_account
	if account == nil {
		logError("No account!")
		return nil, fmt.Errorf("There's no account!")
	}

	// Create the connection object
	connection := commsConnRaven{
		commsConnCommon: commsConnCommon{
			connectionIdsAsMap: 	map[string]bool{}, // Added in AddConnection
			LinkId:             	linkId,
			LinkType:           	linkType,
			Profile:		profile,
		},
		Account: account,
		Rcvrs:   append(make([]string, 0), profile.Rcvr),
		Is_open: false,
	}

	logDebug("OpenConnection: opened connection on host \"", connection.Account.host, "\" with username \"", connection.Account.uname, "\"")
	return &connection, nil
}

// Close the socket associated with the given Connection
// (This will cause the active goroutine that
// is listening on this socket to end.)
func (connection *commsConnRaven) Close() error {
	connection.Is_open = false
	return nil
}

// Open a connection to the destination host and write the given payload message
func (connection *commsConnRaven) Write(msg []byte) error {
	logDebug("Sending Message")

	uuid, err := connection.Account.enqueue(connection.Rcvrs, msg)
	if err != nil {
		logWarning("Error enqueing message: ", err)
		return err
	}
	// note that the sending of the message is actually done in
	// ravenPeriodicSender, which runs continuously
	
	// We sleep until it's actually sent
	for sent_status, _ := connection.Account.check_sent(uuid, true); sent_status != true; sent_status, _ = connection.Account.check_sent(uuid, true) {
	// for connection.Account.check_sent(uuid, true) != true {
	  time.Sleep(time.Millisecond * 100)
	}

	return nil
}

// Open a server socket and accept incoming messages. All received messages will be forwarded
// to the given plugin. This must be executed within a goroutine.
func (connection *commsConnRaven) Receive(plugin *overwrittenMethodsOnCommsPluginRacecar) {
	// XXX: Could this get called multiple times? Might lead to weird behavior

	logDebug("connectionMonitor: Listening on ", connection.Account.host, ":", connection.Account.uname)
	connection.Is_open = true // XXX: Could be in race conditions if this gets called weirdly

	for connection.Is_open {
		logDebug("connectionMonitor: Raven checking mail...")

		msgs, err := connection.Account.rcv()
		if err != nil {
			logError("connectionMonitor: (Raven) Problem receiving: ", err)
		}
		if len(msgs) != 0 {
			logDebug("connectionMonitor: Raven read ", len(msgs), " messages")

			for _, data := range msgs {
				rawData := commsShims.NewByteVector()
				for _, b := range data {
					rawData.Add(b)
				}

				receivedEncPkg := commsShims.NewEncPkg(rawData)
				plugin.raceSdkReceiveEncPkgWrapper(receivedEncPkg, connection.GetConnectionIds())
				commsShims.DeleteByteVector(rawData)
				commsShims.DeleteEncPkg(receivedEncPkg)
			}
		}


		sleep_time := time.Duration(1) * time.Second // Sleep time is currently arbitrary - it ensures a minimum of 1 second between checking the inbox

		time.Sleep(sleep_time)
	}
}

// Forces interface to be a superset of the abstract base class
// Go type to define abstract methods.
type overwrittenMethodsOnCommsPluginRacecar struct {
	sdk               	commsShims.IRaceSdkComms
	connections       	map[string]CommsConn
	connectionsMutex  	sync.RWMutex
	linkProfiles      	map[string]string
	linkProperties    	map[string]commsShims.LinkProperties
	channelStatuses   	map[string]commsShims.ChannelStatus
	recvChannel       	chan int
	requestEmailHandle	uint64
	keyringPath             string
}

// Wrapper for debug level logging using the RACE Logging API call
func logDebug(msg ...interface{}) {
	commsShims.RaceLogLogDebug("[raven]", fmt.Sprint(msg...), "")
}

// Wrapper for info level logging using the RACE Logging API call
func logInfo(msg ...interface{}) {
	commsShims.RaceLogLogInfo("[raven]", fmt.Sprint(msg...), "")
}

// Wrapper for warn level logging using the RACE Logging API call
func logWarning(msg ...interface{}) {
	commsShims.RaceLogLogWarning("[raven]", fmt.Sprint(msg...), "")
}

// Wrapper for error level logging using the RACE Logging API call
func logError(msg ...interface{}) {
	commsShims.RaceLogLogError("[raven]", fmt.Sprint(msg...), "")
}

// LinkPropSetJson represents a list of properties associated with the link. These include
// information useful for TA1/TA3 to choose which links to use for different types of
// communication
type LinkPropSetJson struct {
	Bandwidth_bps int     `json:"bandwidth_bps"`
	Latency_ms    int     `json:"latency_ms"`
	Loss          float32 `json:"loss"`
}

// Creates and returns a new LinkPropSet
func NewLinkPropertySet(json LinkPropSetJson) commsShims.LinkPropertySet {
	propSet := commsShims.NewLinkPropertySet()
	propSet.SetBandwidth_bps(json.Bandwidth_bps)
	propSet.SetLatency_ms(json.Latency_ms)
	propSet.SetLoss(json.Loss)
	return propSet
}

// LinkPropPairJson holds the send and receive properites of a connection. This
// includes a LinkPropSetJson for the send and receive side of the connection.
type LinkPropPairJson struct {
	Send    LinkPropSetJson `json:"send"`
	Receive LinkPropSetJson `json:"receive"`
}

// Creates and returns a new LinkPropPair
func NewLinkPropertyPair(json LinkPropPairJson) commsShims.LinkPropertyPair {
	propPair := commsShims.NewLinkPropertyPair()
	propPair.SetSend(NewLinkPropertySet(json.Send))
	propPair.SetReceive(NewLinkPropertySet(json.Receive))
	return propPair
}

// LinkPropJson represents the complete properties for a given link. This includes
// details about the link, properties (best/worst/expected cases), and what
// type of link the link is
type LinkPropJson struct {
	Linktype        string           `json:"type"`
	Reliable        bool             `json:"reliable"`
	Duration_s      int              `json:"duration_s"`
	Period_s        int              `json:"period_s"`
	Mtu             int              `json:"mtu"`
	Worst           LinkPropPairJson `json:"worst"`
	Best            LinkPropPairJson `json:"best"`
	Expected        LinkPropPairJson `json:"expected"`
	Unicast         bool             `json:"unicast"`
	Multicast       bool             `json:"multicast"`
	Supported_hints []string         `json:"supported_hints"`
}

// Unmarshal the data object into a LinkPropJson
func (t *LinkPropJson) UnmarshalJSON(data []byte) error {
	type alias LinkPropJson
	tmpSet := LinkPropSetJson{
		Bandwidth_bps: -1,
		Latency_ms:    -1,
		Loss:          -1.0,
	}
	tmpPair := LinkPropPairJson{
		Send:    tmpSet,
		Receive: tmpSet,
	}
	tmp := &alias{
		Duration_s: -1,
		Period_s:   -1,
		Mtu:        -1,
		Worst:      tmpPair,
		Best:       tmpPair,
		Expected:   tmpPair,
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	*t = LinkPropJson(*tmp)
	return nil
}

// LinkProfileJson represents a LinkProfile which defines what a link is, how it
// connects, who it connects to, and which nodes an utilize the link
type LinkProfileJson struct {
	ConnectedTo []string     `json:"connectedTo"`
	UtilizedBy  []string     `json:"utilizedBy"`
	Profile     string       `json:"profile"`
	Properties  LinkPropJson `json:"properties"`
}
type DefaultProfileJson struct {
	UtilizedBy  []string     `json:"utilizedBy"`
	Profile     string       `json:"profile"`
	Properties  LinkPropJson `json:"properties"`
}

// LinkProfileListJson represents all of the link profiles
type LinkProfileListJson struct {
	Links []LinkProfileJson `json:"links"`
}
type DefaultProfileListJson struct {
	Links []DefaultProfileJson `json:"links"`
}

// Set the Sdk object and perform minimum work to
// be abe to respond to incoming calls. Do not use any calls
// to raceSdk that require TA1. Use minimal calls to raceSdk.
func (plugin *overwrittenMethodsOnCommsPluginRacecar) Init(pluginConfig commsShims.PluginConfig) commsShims.PluginResponse {
	logInfo("Init called (Raven); foobar")
	defer logInfo("Init returned (Raven)")

	logDebug("etcDirectory: ", pluginConfig.GetEtcDirectory())
	logDebug("auxDataDirectory: ", pluginConfig.GetAuxDataDirectory())
	logDebug("loggingDirectory: ", pluginConfig.GetLoggingDirectory())
	logDebug("tmpDirectory: ", pluginConfig.GetTmpDirectory())
	logDebug("pluginDirectory: ", pluginConfig.GetPluginDirectory())
	plugin.keyringPath = pluginConfig.GetPluginDirectory() + "/raven-keyfile.json"

	plugin.channelStatuses = map[string]commsShims.ChannelStatus{
		RAVEN_GID: commsShims.CHANNEL_UNAVAILABLE,
	}

	plugin.connections = make(map[string]CommsConn)
	plugin.linkProfiles = make(map[string]string)
	plugin.linkProperties = make(map[string]commsShims.LinkProperties)

	bytesToWrite := commsShims.NewByteVector()
	for _, b := range []byte("Georgetown-NRL-Tor Raven Golang Plugin Initialized\n") {
		bytesToWrite.Add(b)
	}
	responseStatus := plugin.sdk.WriteFile("initialized.txt", bytesToWrite).GetStatus()
	if responseStatus != commsShims.SDK_OK {
		logError("Failed to write initialized.txt")
	}
	bytesRead := plugin.sdk.ReadFile("initialized.txt")
	bytes := []byte{}
	if bytesRead.Size() >= 2<<32 {
		logError("File too large, only reading first 2^32 bytes")
	}
	for idx := 0; idx < int(bytesRead.Size()); idx++ {
		bytes = append(bytes, bytesRead.Get(idx))
	}
	stringRead := string(bytes)
	logDebug("Read Initialization File: ", stringRead)

	return commsShims.PLUGIN_OK
}

// Shutdown the plugin. Close open connections, remove state, etc.
func (plugin *overwrittenMethodsOnCommsPluginRacecar) Shutdown() commsShims.PluginResponse {
	logInfo("Shutdown: called")
	handle := commsShims.GetNULL_RACE_HANDLE()
	for connectionId, _ := range plugin.connections {
		plugin.CloseConnection(handle, connectionId)
	}
	logInfo("Shutdown: returned")
	return commsShims.PLUGIN_OK
}

// Get link properties for the specified link
func (plugin *overwrittenMethodsOnCommsPluginRacecar) GetLinkProperties(linkType commsShims.LinkType, linkId string) commsShims.LinkProperties {
	logInfo("GetLinkProperties called")
	if props, ok := plugin.linkProperties[linkId]; ok {
		return props
	}
	return commsShims.NewLinkProperties()
}

// Get connection properties for the specified connection
func (plugin *overwrittenMethodsOnCommsPluginRacecar) GetConnectionProperties(linkType commsShims.LinkType, connectionId string) commsShims.LinkProperties {
	logInfo("GetConnectionProperties called")
	if conn, conn_exists := plugin.connections[connectionId]; conn_exists {
		if props, link_exists := plugin.linkProperties[conn.GetLinkId()]; link_exists {
			return props
		}
	}
	return commsShims.NewLinkProperties()
}

// Send an encrypted package
func (plugin *overwrittenMethodsOnCommsPluginRacecar) SendPackage(handle uint64, connectionId string, encPkg commsShims.EncPkg, timeoutTimestamp float64, batchId uint64) commsShims.PluginResponse {
	defer commsShims.DeleteEncPkg(encPkg)

	logInfo("SendPackage called (Raven)")
	defer logInfo("SendPackage returned (Raven)")

	// get the raw bytes out of the Encrypted Package
	msg_vec := encPkg.GetRawData()
	defer commsShims.DeleteByteVector(msg_vec)
	msg := make([]byte, 0, msg_vec.Size())
	msg_size := int(msg_vec.Size())
	for i := 0; i < msg_size; i++ {
		msg = append(msg, msg_vec.Get(i))
	}

	// get the connection associated with the specified connection ID
	plugin.connectionsMutex.RLock()
	connection, ok := plugin.connections[connectionId]
	plugin.connectionsMutex.RUnlock()
	if !ok {
		logError("failed to find connection with ID = ", connectionId)
		plugin.sdk.OnPackageStatusChanged(handle, commsShims.PACKAGE_FAILED_GENERIC, commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	if err := connection.Write(msg); err != nil {
		plugin.sdk.OnPackageStatusChanged(handle, commsShims.PACKAGE_FAILED_GENERIC, commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	plugin.sdk.OnPackageStatusChanged(handle, commsShims.PACKAGE_SENT, commsShims.GetRACE_BLOCKING())
	return commsShims.PLUGIN_OK
}

// Open a connection with a given type on the specified link. Additional configuration
// info can be provided via the linkHints param.
func (plugin *overwrittenMethodsOnCommsPluginRacecar) OpenConnection(handle uint64, linkType commsShims.LinkType, linkId string, link_hints string, send_timeout int) commsShims.PluginResponse {
	logInfo("OpenConnection: called")
	logDebug("OpenConnection:    type = ", linkType)
	logDebug("OpenConnection:    Link ID = ", linkId)
	logDebug("OpenConnection:    link_hints = ", link_hints)
	logDebug("OpenConnection:    send_timeout = ", send_timeout)
	defer logInfo("OpenConnection: returned")

	if _, ok := plugin.linkProperties[linkId]; !ok {
		logError("OpenConnection:failed to find link with ID = ", linkId)
		return commsShims.PLUGIN_ERROR
	}

	//targetPersonas := plugin.sdk.GetPersonasForLink(linkId)
	//logDebug("target personas = ", targetPersonas)

	newConnectionId := plugin.sdk.GenerateConnectionId(linkId)
	logDebug("OpenConnection: opening new connection with ID: ", newConnectionId)
	linkProperties := plugin.linkProperties[linkId]
	logDebug("OpenConnection: properties for connection ID ", newConnectionId, " are ", linkProperties)

	// Check if there is already an open connection that can be reused.
	plugin.connectionsMutex.Lock()
	for _, connection := range plugin.connections {
		if connection.GetLinkId() == linkId && connection.GetLinkType() == linkType {
			plugin.addConnection(newConnectionId, connection)
			plugin.connectionsMutex.Unlock()
			plugin.sdk.OnConnectionStatusChanged(handle, newConnectionId, commsShims.CONNECTION_OPEN, linkProperties, commsShims.GetRACE_BLOCKING())
			return commsShims.PLUGIN_OK
		}
	}
	plugin.connectionsMutex.Unlock()

	// Get the Link Profile with the specified ID
	linkProfile, ok := plugin.linkProfiles[linkId]
	if !ok {
		logError("OpenConnection:failed to find link profile for link with ID = ", linkId)
		plugin.sdk.OnConnectionStatusChanged(handle, newConnectionId, commsShims.CONNECTION_CLOSED, linkProperties, commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	var connection CommsConn
	var err error
	if linkProperties.GetTransmissionType() == commsShims.TT_MULTICAST {
		err = fmt.Errorf("Raven does not support multicast")
	} else {
		connection, err = newRavenConn(newConnectionId, linkType, linkId, linkProfile)
	}

	if err != nil {
		logError("OpenConnection: Raven failed to create connection: ", err)
		plugin.sdk.OnConnectionStatusChanged(handle, newConnectionId, commsShims.CONNECTION_CLOSED, linkProperties, commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	// Add the connection to the Plugin's list of all active connections
	plugin.connectionsMutex.Lock()
	plugin.addConnection(newConnectionId, connection)
	plugin.connectionsMutex.Unlock()

	// Start a listener (in a new goroutine) if the Link Type allows receipt of messages
	if linkType == commsShims.LT_RECV || linkType == commsShims.LT_BIDI {
		logDebug("OpenConnection:Starting Connection Monitor with connection ID(s): ", strings.Join(connection.GetConnectionIds(), ", "))
		go plugin.connectionMonitor(connection)
	}

	// Update the SDK about the connection being open
	plugin.sdk.OnConnectionStatusChanged(handle, newConnectionId, commsShims.CONNECTION_OPEN, linkProperties, commsShims.GetRACE_BLOCKING())

	// Return success
	return commsShims.PLUGIN_OK

}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) addConnection(newConnectionId string, connection CommsConn) {
	plugin.connections[newConnectionId] = connection
	connection.AddConnectionId(newConnectionId)
}

// Close a connection with a given ID.
func (plugin *overwrittenMethodsOnCommsPluginRacecar) CloseConnection(handle uint64, connectionId string) commsShims.PluginResponse {
	logInfo("CloseConnection: called")
	defer logInfo("CloseConnection: returned")

	plugin.connectionsMutex.Lock()
	defer plugin.connectionsMutex.Unlock()
	if connection, ok := plugin.connections[connectionId]; ok {
		logDebug("CloseConnection: Raven closing connection with ID ", connectionId)
		if connection.RemoveConnectionId(connectionId) == 0 {
			logDebug("CloseConnection: last connection ID has closed, shutting down connection")
			if err := connection.Close(); err != nil {
				logError("CloseConnection: error occurred closing connection ", connectionId, ": ", err.Error())
			}
		}
		delete(plugin.connections, connectionId)

		// Update the SDK that the connection has been closed
		plugin.sdk.OnConnectionStatusChanged(handle, connectionId, commsShims.CONNECTION_CLOSED, plugin.linkProperties[connection.GetLinkId()], commsShims.GetRACE_BLOCKING())
	} else {
		logError("CloseConnection:unable to find connection with ID = ", connectionId)
		return commsShims.PLUGIN_ERROR
	}

	// Return success to the SDK
	return commsShims.PLUGIN_OK
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) DestroyLink(handle uint64, linkId string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("DestroyLink: (handle: %v, link ID: %v): ", handle, linkId)
	logDebug(logPrefix, "called")
	if _, ok := plugin.linkProperties[linkId]; !ok {
		logDebug(logPrefix, "unknown link ID")
		return commsShims.PLUGIN_ERROR
	}

	plugin.sdk.OnLinkStatusChanged(handle, linkId, commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())

	// Close all theonnections for the given link.
	plugin.connectionsMutex.Lock()
	defer plugin.connectionsMutex.Unlock()
	for connectionId, connection := range plugin.connections {
		if connection.GetLinkId() == linkId {
			// Makes call to OnConnectionStatusChanged.
			plugin.CloseConnection(handle, connectionId)
		}
	}

	delete(plugin.linkProfiles, linkId)
	delete(plugin.linkProperties, linkId)

	logDebug(logPrefix, "returned")
	return commsShims.PLUGIN_OK
}


func (plugin *overwrittenMethodsOnCommsPluginRacecar) CreateLink(handle uint64, channelGid string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("CreateLink: (handle: %v, channel GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")

	if status, ok := plugin.channelStatuses[channelGid]; !ok || status != commsShims.CHANNEL_AVAILABLE {
		logError(logPrefix, "channel not available")
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	linkId := plugin.sdk.GenerateLinkId(channelGid)
	if linkId == "" {
		logError("CreateLink: SDK failed to generate link ID. Is the channel GID valid? ", channelGid)
		return commsShims.PLUGIN_ERROR
	}

	linkProps, err := getDefaultLinkPropertiesForChannel(plugin.sdk, channelGid)
	if err != nil {
		logError(logPrefix, "failed to get default channel properties: ", err)
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	} else {
		logDebug(logPrefix, "link properties are ", linkProps)
	}

	if channelGid == RAVEN_GID {
		logDebug(logPrefix, "Creating Raven indirect link with ID: ", linkId)

		linkProps.SetLinkType(commsShims.LT_RECV)

		rcvr := established_account.uname
		if err != nil {
			logError(logPrefix, "Failed to get a listener: ", err)
			plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
			return commsShims.PLUGIN_ERROR
		}
		
		
		linkProfile := unicastProfile{
			Sender: "", // This should be the link loaders email
			Rcvr: rcvr,
		}
		linkProfileJson, jsonErr := json.Marshal(linkProfile)
		if jsonErr != nil {
			logError(logPrefix, "failed to convert link profile to json: ", jsonErr.Error())
			plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
			return commsShims.PLUGIN_ERROR
		}


		linkProps.SetLinkAddress(string(linkProfileJson))

		// XXX: Raven should store a recieve link for this link profile
		plugin.linkProperties[linkId] = linkProps
		plugin.linkProfiles[linkId] = string(linkProfileJson)

		linkProps.SetTransmissionType(commsShims.TT_UNICAST)
		linkProps.SetConnectionType(commsShims.CT_INDIRECT)
		linkProps.SetSendType(commsShims.ST_STORED_ASYNC)


		plugin.sdk.OnLinkStatusChanged(handle, linkId, commsShims.LINK_CREATED, linkProps, commsShims.GetRACE_BLOCKING())
		plugin.sdk.UpdateLinkProperties(linkId, linkProps, commsShims.GetRACE_BLOCKING())

		logDebug(logPrefix, "created indirect link with link address: ", string(linkProfileJson))
	} else {
		logError(logPrefix, "invalid channel GID")
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	logDebug(logPrefix, "returned")
	return commsShims.PLUGIN_OK
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) CreateLinkFromAddress(handle uint64, channelGid string, linkAddress string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("CreateLinkFromAddress: (handle: %v, channel GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")

	if status, ok := plugin.channelStatuses[channelGid]; !ok || status != commsShims.CHANNEL_AVAILABLE {
		logError(logPrefix, "channel not available")
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	linkId := plugin.sdk.GenerateLinkId(channelGid)
	if linkId == "" {
		logError("CreateLinkFromAddress: SDK failed to generate link ID. Is th channel GID valid? ", channelGid)
		return commsShims.PLUGIN_ERROR
	}

	linkProps, err := getDefaultLinkPropertiesForChannel(plugin.sdk, channelGid)
	if err != nil {
		logError(logPrefix, "failed to get default channel properties: ", err)
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	linkProps.SetLinkAddress(string(linkAddress))
	if channelGid == RAVEN_GID {
		logDebug(logPrefix, "Creating TwoSix direct link with ID: ", linkId)

		linkProps.SetLinkType(commsShims.LT_RECV)

		var profile unicastProfile
		err := json.Unmarshal([]byte(linkAddress), &profile)
		if err != nil {
			logError(logPrefix, "failed to parse link address: ", linkAddress, ". Error: ", err)
			plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
			return commsShims.PLUGIN_ERROR
		}
		
		sender := established_account.uname
		if sender == "" {
			logError(logPrefix, "failed to parse link address: ", linkAddress, ". Error: ", err)
			plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
			return commsShims.PLUGIN_ERROR
		}

		if profile.Sender == "" {
			profile.Sender = sender
		}

		plugin.linkProperties[linkId] = linkProps
		plugin.linkProfiles[linkId] = linkAddress

		plugin.sdk.OnLinkStatusChanged(handle, linkId, commsShims.LINK_CREATED, linkProps, commsShims.GetRACE_BLOCKING())
		plugin.sdk.UpdateLinkProperties(linkId, linkProps, commsShims.GetRACE_BLOCKING())

		logDebug(logPrefix, "Created direct link with link address: ", linkAddress)
	} else {
		logError(logPrefix, "invalid channel GID")
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	logDebug("%v returned", logPrefix)
	return commsShims.PLUGIN_OK
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) LoadLinkAddress(handle uint64, channelGid string, linkAddress string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("LoadLinkAddress: (handle: %v, channel GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")

	if status, ok := plugin.channelStatuses[channelGid]; !ok || status != commsShims.CHANNEL_AVAILABLE {
		logError(logPrefix, "channel not available")
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	linkId := plugin.sdk.GenerateLinkId(channelGid)
	if linkId == "" {
		logError("LoadLinkAddress: SDK failed to generate link ID. Is the channel GID valid? ", channelGid)
		return commsShims.PLUGIN_ERROR
	}

	linkProps, err := getDefaultLinkPropertiesForChannel(plugin.sdk, channelGid)
	if err != nil {
		logError(logPrefix, "failed to get default channel properties: ", err)
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	if channelGid == RAVEN_GID {
		logDebug(logPrefix, "Loading Raven indirect link with ID: ", linkId)

		linkProps.SetLinkType(commsShims.LT_SEND)

		var profile unicastProfile
		err := json.Unmarshal([]byte(linkAddress), &profile)
		if err != nil {
			logError(logPrefix, "failed to parse link address: ", linkAddress, ". Error: ", err)
			plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
			return commsShims.PLUGIN_ERROR
		}

		sender := established_account.uname
		if sender == "" {
			logError(logPrefix, "failed to parse link address: ", linkAddress, ". Error: ", err)
			plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
			return commsShims.PLUGIN_ERROR
		}

		if profile.Sender == "" {
			profile.Sender = sender
		}

		plugin.linkProperties[linkId] = linkProps
		plugin.linkProfiles[linkId] = linkAddress

		plugin.sdk.OnLinkStatusChanged(handle, linkId, commsShims.LINK_LOADED, linkProps, commsShims.GetRACE_BLOCKING())
		plugin.sdk.UpdateLinkProperties(linkId, linkProps, commsShims.GetRACE_BLOCKING())

		logDebug(logPrefix, "Loaded indirect link with link address: ", linkAddress)
	} else {
		logError(logPrefix, "invalid channel GID")
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	logDebug(logPrefix, " returned")
	return commsShims.PLUGIN_OK
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) LoadLinkAddresses(handle uint64, channelGid string, linkAddresses commsShims.StringVector) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("LoadLinkAddress: (handle: %v, channel GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called with link addresses: ", linkAddresses)
	logError(logPrefix, "API not supported for any TwoSix channels")
	plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
	logDebug(logPrefix, "returned")
	return commsShims.PLUGIN_ERROR
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) ActivateChannel(handle uint64, channelGid string, roleName string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("ActivateChannel: (handle: %v, channel GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")

	status, ok := plugin.channelStatuses[channelGid]
	if !ok {
		logError(logPrefix, "unknown channel GID")
		return commsShims.PLUGIN_ERROR
	}

	if status == commsShims.CHANNEL_AVAILABLE {
		return commsShims.PLUGIN_OK
	}

	if channelGid == RAVEN_GID {
		plugin.channelStatuses[channelGid] = commsShims.CHANNEL_STARTING
		
		response := plugin.sdk.RequestPluginUserInput("emailProfile", "What is the your email profile?", true)
		if response.GetStatus() != commsShims.SDK_OK {
			logError("Failed to request email account from user, direct channel cannot be used")
			plugin.channelStatuses[RAVEN_GID] = commsShims.CHANNEL_FAILED
			channelProps := getDefaultChannelPropertiesForChannel(plugin.sdk, RAVEN_GID)
			plugin.sdk.OnChannelStatusChanged(
				commsShims.GetNULL_RACE_HANDLE(),
				RAVEN_GID,
				commsShims.CHANNEL_FAILED,
				channelProps,
				commsShims.GetRACE_BLOCKING(),
			)
			// Don't continue
			return commsShims.PLUGIN_OK
		}
		plugin.requestEmailHandle = response.GetHandle()
	}

	logDebug(logPrefix, "returned")
	return commsShims.PLUGIN_OK
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) DeactivateChannel(handle uint64, channelGid string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("DeactivateChannel: (handle: %v, channel GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")

	status, ok := plugin.channelStatuses[channelGid]
	if !ok {
		logError(logPrefix, "unknown channel GID")
		return commsShims.PLUGIN_ERROR
	}

	plugin.channelStatuses[channelGid] = commsShims.CHANNEL_UNAVAILABLE
	plugin.sdk.OnChannelStatusChanged(handle, channelGid, commsShims.CHANNEL_UNAVAILABLE, commsShims.NewChannelProperties(), commsShims.GetRACE_BLOCKING())

	if status == commsShims.CHANNEL_UNAVAILABLE {
		return commsShims.PLUGIN_OK
	}

	linkIdsToDestroy := []string{}
	for linkId, linkProps := range plugin.linkProperties {
		if linkProps.GetChannelGid() == channelGid {
			linkIdsToDestroy = append(linkIdsToDestroy, linkId)
		}
	}

	for _, linkId := range linkIdsToDestroy {
		// Calls OnLinkStatusChanged to notify SDK that links have been destroyed and call OnConnectionStatusChanged to notify all connnections in each link have been destroyed.
		plugin.DestroyLink(handle, linkId)
	}

	logDebug(logPrefix, "returned")
	return commsShims.PLUGIN_OK
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) OnUserInputReceived(handle uint64, answered bool, response string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("OnUserInputReceived: (handle: %v): ", handle)
	logDebug(logPrefix, "called")
	
	var err error
	
	logDebug(logPrefix, "PATH: " + plugin.keyringPath)
	if handle == plugin.requestEmailHandle {
		logDebug(logPrefix, "handle was expected")
		if answered {
			logDebug(logPrefix, "was answered")
			var act email_account
			logDebug(logPrefix, "unmarshaling")
			err = json.Unmarshal([]byte(response), &act)
			if err != nil {
				logError("failed to read account json: ", err)
			} else {
				logDebug(logPrefix, "unmarshaled")
				_, err = initializeAccountStruct(act.EmailServer, act.SmtpPort, act.ImapPort, act.Address, act.Password, act.InsecureTLS, plugin.keyringPath)
				logDebug(logPrefix, "initialized")
				if err != nil {
					logError("failed to init account: ", err)
				} else {
					logInfo(logPrefix, "initialized account ", act)
				}
			}
		}
		if !answered || err != nil {
			logError(logPrefix, "direct channel not available without emailAccount")
			plugin.channelStatuses[RAVEN_GID] = commsShims.CHANNEL_DISABLED
			channelProps := getDefaultChannelPropertiesForChannel(plugin.sdk, RAVEN_GID)
			plugin.sdk.OnChannelStatusChanged(
				commsShims.GetNULL_RACE_HANDLE(),
				RAVEN_GID,
				commsShims.CHANNEL_DISABLED,
				channelProps,
				commsShims.GetRACE_BLOCKING(),
			)
			// Do not continue handling input
			return commsShims.PLUGIN_OK
		}

		plugin.requestEmailHandle = 0
	}
	
	logDebug(logPrefix, "checking if everything was fulfilled")
	// Check if all requests have been fulfilled
	if plugin.requestEmailHandle == 0 {
		logDebug(logPrefix, "setting to available")
		plugin.channelStatuses[RAVEN_GID] = commsShims.CHANNEL_AVAILABLE
		logDebug(logPrefix, "gettingdefault propts")
		channelProps := getDefaultChannelPropertiesForChannel(plugin.sdk, RAVEN_GID)
		logDebug(logPrefix, "changing status")
		plugin.sdk.OnChannelStatusChanged(
			commsShims.GetNULL_RACE_HANDLE(),
			RAVEN_GID,
			commsShims.CHANNEL_AVAILABLE,
			channelProps,
			commsShims.GetRACE_BLOCKING(),
		)
		logDebug(logPrefix, "displaying")
		plugin.sdk.DisplayInfoToUser(fmt.Sprintf("%v is available", RAVEN_GID), commsShims.UD_TOAST)
	}

	logDebug(logPrefix, "returned")
	return commsShims.PLUGIN_OK
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) FlushChannel(handle uint64, channelGid string, batchId uint64) commsShims.PluginResponse {
	logError("FlushChannel: plugin does not support flushing")
	return commsShims.PLUGIN_ERROR
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) OnUserAcknowledgementReceived(handle uint64) commsShims.PluginResponse {
	logDebug("OnUserAcknowledgementReceived: called")
	return commsShims.PLUGIN_OK
}

// TODO: this wrapper function is used for convenience until a SWIG typemap is created for std::vector<std::string> to []string.
func (plugin *overwrittenMethodsOnCommsPluginRacecar) raceSdkReceiveEncPkgWrapper(encPkg commsShims.EncPkg, connectionIds []string) {
	connectionIdsVector := commsShims.NewStringVector()
	defer commsShims.DeleteStringVector(connectionIdsVector)
	for _, persona := range connectionIds {
		connectionIdsVector.Add(persona)
	}

	// Send EncPkg to the SDK for processing
	response := plugin.sdk.ReceiveEncPkg(encPkg, connectionIdsVector, commsShims.GetRACE_BLOCKING())

	// Handle Success/Failure
	responseStatus := response.GetStatus()
	if responseStatus != commsShims.SDK_OK {
		logError("Failed sending encPkg for connections ", connectionIdsVector.Size(), " to the SDK: ", responseStatus)
	}
}

func (plugin *overwrittenMethodsOnCommsPluginRacecar) connectionMonitor(connection CommsConn) {
	logInfo("connectionMonitor: called")
	defer logInfo("connectionMonitor: returned")
	connection.Receive(plugin)
	logInfo("connectionMonitor: Shutting down")
	plugin.recvChannel <- 1
}

var plugin *overwrittenMethodsOnCommsPluginRacecar = nil

func InitCommsPluginRacecar(sdk uintptr) {
	logInfo("InitCommsPluginRacecar: called")
	if plugin != nil {
		logWarning("Trying to construct a new Golang plugin when one has been created already")
		return
	}

	plugin = &overwrittenMethodsOnCommsPluginRacecar{}
	plugin.sdk = commsShims.SwigcptrIRaceSdkComms(sdk)

	logInfo("InitCommsPluginRacecar: returned")
}

//export CreatePluginCommsGolang
func CreatePluginCommsGolang(sdk uintptr) {
	logInfo("CreatePluginCommsGolang: called")
	InitCommsPluginRacecar(sdk)
	logInfo("CreatePluginCommsGolang: returned")
}

//export DestroyPluginCommsGolang
func DestroyPluginCommsGolang() {
	logInfo("DestroyPluginCommsGolang: called")
	if plugin != nil {
		plugin = nil
	}
	logInfo("DestroyPluginCommsGolang: returned")
}

// For some reason, commsShims.PluginResponse, etc. are not recognized as exportable types
type PluginResponse int
type LinkType int

// Swig didn't bother to export this function, so here it is, copied straight from
// commsPluginBindingsGolang.go all its glory (or should I say... gory). We need this
// in order to properly free memory allocated by C++.
type swig_gostring struct {
	p uintptr
	n int
}

func swigCopyString(s string) string {
	p := *(*swig_gostring)(unsafe.Pointer(&s))
	r := string((*[0x7fffffff]byte)(unsafe.Pointer(p.p))[:p.n])
	commsShims.Swig_free(p.p)
	return r
}

//export PluginCommsGolangInit
func PluginCommsGolangInit(pluginConfig uintptr) PluginResponse {
	return PluginResponse(plugin.Init(commsShims.SwigcptrPluginConfig(pluginConfig)))
}

//export PluginCommsGolangShutdown
func PluginCommsGolangShutdown() PluginResponse {
	return PluginResponse(plugin.Shutdown())
}

//export PluginCommsGolangSendPackage
func PluginCommsGolangSendPackage(handle uint64, connectionId string, encPkg uintptr, timeoutTimestamp float64, batchId uint64) PluginResponse {
	return PluginResponse(plugin.SendPackage(handle, swigCopyString(connectionId), commsShims.SwigcptrEncPkg(encPkg), timeoutTimestamp, batchId))
}

//export PluginCommsGolangOpenConnection
func PluginCommsGolangOpenConnection(handle uint64, linkType LinkType, linkId string, link_hints string, send_timeout int) PluginResponse {
	return PluginResponse(plugin.OpenConnection(handle, commsShims.LinkType(linkType), swigCopyString(linkId), link_hints, send_timeout))
}

//export PluginCommsGolangCloseConnection
func PluginCommsGolangCloseConnection(handle uint64, connectionId string) PluginResponse {
	return PluginResponse(plugin.CloseConnection(handle, swigCopyString(connectionId)))
}

//export PluginCommsGolangDestroyLink
func PluginCommsGolangDestroyLink(handle uint64, linkId string) PluginResponse {
	return PluginResponse(plugin.DestroyLink(handle, swigCopyString(linkId)))
}

//export PluginCommsGolangCreateLink
func PluginCommsGolangCreateLink(handle uint64, channelGid string) PluginResponse {
	return PluginResponse(plugin.CreateLink(handle, swigCopyString(channelGid)))
}

//export PluginCommsGolangCreateLinkFromAddress
func PluginCommsGolangCreateLinkFromAddress(handle uint64, channelGid string, linkAddress string) PluginResponse {
	return PluginResponse(plugin.CreateLinkFromAddress(handle, swigCopyString(channelGid), swigCopyString(linkAddress)))
}

//export PluginCommsGolangLoadLinkAddress
func PluginCommsGolangLoadLinkAddress(handle uint64, channelGid string, linkAddress string) PluginResponse {
	return PluginResponse(plugin.LoadLinkAddress(handle, swigCopyString(channelGid), swigCopyString(linkAddress)))
}

//export PluginCommsGolangLoadLinkAddresses
func PluginCommsGolangLoadLinkAddresses(handle uint64, channelGid string, linkAddresses uintptr) PluginResponse {
	return PluginResponse(plugin.LoadLinkAddresses(handle, swigCopyString(channelGid), commsShims.SwigcptrStringVector(linkAddresses)))
}

//export PluginCommsGolangDeactivateChannel
func PluginCommsGolangDeactivateChannel(handle uint64, channelGid string) PluginResponse {
	return PluginResponse(plugin.DeactivateChannel(handle, swigCopyString(channelGid)))
}

//export PluginCommsGolangActivateChannel
func PluginCommsGolangActivateChannel(handle uint64, channelGid string, roleName string) PluginResponse {
	return PluginResponse(plugin.ActivateChannel(handle, swigCopyString(channelGid), swigCopyString(roleName)))
}

//export PluginCommsGolangOnUserInputReceived
func PluginCommsGolangOnUserInputReceived(handle uint64, answered bool, response string) PluginResponse {
	return PluginResponse(plugin.OnUserInputReceived(handle, answered, swigCopyString(response)))
}

//export PluginCommsGolangFlushChannel
func PluginCommsGolangFlushChannel(handle uint64, connId string, batchId uint64) PluginResponse {
	return PluginResponse(plugin.FlushChannel(handle, swigCopyString(connId), batchId))
}

//export PluginCommsGolangOnUserAcknowledgementReceived
func PluginCommsGolangOnUserAcknowledgementReceived(handle uint64) PluginResponse {
	return PluginResponse(plugin.OnUserAcknowledgementReceived(handle))
}

// TODO
func main() {}

/**
Enters an infinite loop and calls send() periodically.

This function MUST be executed as a go thread.
*/
func ravenPeriodicSender(act *account) {
	logDebug("launching Raven's periodic sender scheduler")
	for {
		err := act.send()
		if err != nil {
			logError("send failed:", err)
		}
		time.Sleep(time.Millisecond * 250)
	}
}
