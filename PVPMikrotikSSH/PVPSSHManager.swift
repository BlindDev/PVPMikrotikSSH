//
//  PVPConnectionManager.swift
//  PVPMikrotikSSH
//
//  Created by Pavel Popov on 22.04.17.
//  Copyright © 2017 Pavel Popov. All rights reserved.
//

import Foundation
import NMSSH

@objc public protocol PVPSSHManagerDelegate {
    @objc optional func sessionDidDisconnectWithError(error: Error)
    @objc optional func channelDidReadData(message: String)
    @objc optional func channelDidReadError(error: String)
    @objc optional func channelShellDidClose()
    @objc optional func additionalErrorReceived(error: Error)
}

open class PVPSSHManager: NSObject {
    
    //fileprivate log-in variables
    fileprivate let host: String
    fileprivate let userName: String
    fileprivate var password: String?
    
    //NMSSH vars
    fileprivate var session: NMSSHSession?
    fileprivate var channel: NMSSHChannel? {
        return session?.channel
    }
    
    //Queues
    fileprivate let sshQueue = DispatchQueue(label: "SSH Queue")
    fileprivate let mainQueue = DispatchQueue.main
    
    
    //initialization
    init(host: String, userName: String, password: String? = nil) {
        self.host = host
        self.userName = userName
        self.password = password
    }
    
    //delegate
    var delegate: PVPSSHManagerDelegate?
    
    //computed vars
    var isConnected: Bool {
        return session?.isConnected ?? false
    }
    
    var isAuthorized: Bool {
        return session?.isAuthorized ?? false
    }
}

//MARK: - Commands methods
extension PVPSSHManager{
    //send command
    internal func sendCommand(command: String, completionHandler: @escaping (_ error: PVPError?) -> Void) {
        
        if let channel = channel {
            sshQueue.async {
                self.sendCommand(channel: channel, command: command, completionHandler: completionHandler)
            }
        }else{
            completionHandler(PVPError.noSessionChannel)
        }
    }
    
    //func send command inside ssh queue
    fileprivate func sendCommand(channel: NMSSHChannel, command: String, completionHandler: @escaping (_ error: PVPError?) -> Void) {
        do {
            
            try channel.write(command)
            
        }catch let error {
            
            mainQueue.async {
                completionHandler(PVPError.errorWritingCommand(command: command, error: error))
            }
        }
    }
    
    //execute command
    internal func executeCommand(command: String, completionHandler: @escaping (_ error: PVPError?, _ string: String?) -> Void) {
        
        if let channel = channel {
            sshQueue.async {
                self.executeCommand(channel: channel, command: command, completionHandler: completionHandler)
            }
        }else{
            completionHandler(PVPError.noSessionChannel, nil)
        }
    }
    
    //execute command inside ssh queue
    fileprivate func executeCommand(channel: NMSSHChannel, command: String, completionHandler: @escaping (_ error: PVPError?, _ string: String?) -> Void) {
        do {
            
            let response = try channel.execute(command)
            
            mainQueue.async {
                completionHandler(nil, response)
            }
        }catch let error {
            
            mainQueue.async {
                completionHandler(PVPError.errorExecutingCommand(command: command, error: error), nil)
            }
        }
    }
}

//MARK: - Session public methods
extension PVPSSHManager {
    
    //initiating session. Set startShell true for use sending commands, false for use executing commands
    func initiateSessionAndAuthorize(startShell: Bool = false, completionHandler: @escaping (_ error: PVPError?) -> Void) {
        
        guard let pass = password else{
            
            completionHandler(PVPError.noPassword)
            return
        }
        //if we already have a session, disconnect then
        if isConnected {
            disconnect()
            session = nil
        }
        
        //all methods should call inside ssh queue
        sshQueue.async {
            
            //initiating session
            self.session = NMSSHSession.connect(toHost: self.host, withUsername: self.userName)
            self.session?.delegate = self
            
            //check if session is not connected
            if self.isConnected == false {
                self.mainQueue.async {
                    completionHandler(PVPError.notConnected)
                }
                return
            }
            
            //authenticating
            let authorized = self.session?.authenticate(byPassword: pass)
            
            //check if session is not authenticated
            if authorized == false {
                self.mainQueue.async {
                    completionHandler(PVPError.notAuthorized)
                }
                return
            }
            
            //start shell if needed
            if startShell {
                self.startShell(completionHandler: completionHandler)
            }else{
                //small hold before complete
                let deadLine = DispatchTime.now() + 0.5
                
                self.mainQueue.asyncAfter(deadline: deadLine) {
                    completionHandler(nil)
                }
            }
        }
    }
    
    func disconnect() {
        if let session = session {
            sshQueue.async {
                session.disconnect()
            }
        }
    }
    
    func connect() {
        if let session = session {
            sshQueue.async {
                session.connect()
            }
        }
    }
    
    func authenticate() {
        if let session = session, let pass = password {
            sshQueue.async {
                session.authenticate(byPassword: pass)
            }
        }
    }
    
    func startShell(completionHandler: @escaping (_ error: PVPError?) -> Void) {
        if let channel = channel {
            channel.delegate = self
            channel.requestPty = true
            
            //trying to start
            sshQueue.async {
                do {
                    try channel.startShell()
                    
                    let deadLine = DispatchTime.now() + 2.0
                    
                    self.mainQueue.asyncAfter(deadline: deadLine) {
                        completionHandler(nil)
                    }
                }catch let error {
                    self.mainQueue.async {
                        completionHandler(PVPError.shellNotStarted(error: error))
                    }
                }
                
            }
        }
    }
    
    func closeShell() {
        if let channel = channel {
            
            sshQueue.async {
                channel.closeShell()
            }
        }
    }
}

//MARK: - NMSSH Session Delegate
extension PVPSSHManager: NMSSHSessionDelegate {
    
    public func session(_ session: NMSSHSession!, didDisconnectWithError error: Error!) {
        //use main queue to use this code for an interface
        mainQueue.async {
            self.delegate?.sessionDidDisconnectWithError?(error: error)
        }
    }
}

//MARK: - NMSSH Channel Delegate
extension PVPSSHManager: NMSSHChannelDelegate {
    
    public func channel(_ channel: NMSSHChannel!, didReadError error: String!) {
        //use main queue to use this code for an interface
        mainQueue.async {
            self.delegate?.channelDidReadError?(error: error)
        }
    }
    
    public func channel(_ channel: NMSSHChannel!, didReadData message: String!) {
        //use main queue to use this code for an interface
        mainQueue.async {
            self.delegate?.channelDidReadData?(message: message)
        }
    }
    
    public func channelShellDidClose(_ channel: NMSSHChannel!) {
        //use main queue to use this code for an interface
        mainQueue.async {
            self.delegate?.channelShellDidClose?()
        }
        
    }
}
