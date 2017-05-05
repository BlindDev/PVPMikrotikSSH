//
//  PVPError.swift
//  PVPMikrotikSSH
//
//  Created by Pavel Popov on 05.05.17.
//  Copyright © 2017 Pavel Popov. All rights reserved.
//

import Foundation

enum PVPError {
    
    case errorWritingCommand(command: String, error: Error)
    case errorExecutingCommand(command: String, error: Error)
    case noPassword
    case notConnected
    case notAuthorized
    case noSessionChannel
    case shellNotStarted(error: Error)
}
