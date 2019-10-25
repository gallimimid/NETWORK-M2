# template
template = {
'1.5.1': {
    'accountService': {
        'name': 'Account',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'MinimumPasswordLength': 'features.accountService.data.dmeData.passwordRules.strength.minLength',
            'MinUpperCase': 'features.accountService.data.dmeData.passwordRules.strength.minUpperCase',
            'MinLowerCase': 'features.accountService.data.dmeData.passwordRules.strength.minLowerCase',
            'MinDigit': 'features.accountService.data.dmeData.passwordRules.strength.minDigit',
            'MinSpecialCharacter': 'features.accountService.data.dmeData.passwordRules.strength.minSpecialCharacter',
            'ExpirationEnabled': 'features.accountService.data.dmeData.passwordRules.expiration.enabled',
            'ExpiresAfterDays': 'features.accountService.data.dmeData.passwordRules.expiration.afterDays',
            'DefaultAccountNeverExpires': 'features.accountService.data.dmeData.passwordRules.expiration.defaultAccountNeverExpires',
            'LockoutRulesEnabled': 'features.accountService.data.dmeData.lockoutRules.enabled',
            'Threshold': 'features.accountService.data.dmeData.lockoutRules.threshold',
            'DefaultAccountNeverBlocks': 'features.accountService.data.dmeData.lockoutRules.defaultAccountNeverBlocks'
        }
    },
    'card': {
        'name': 'Card',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'Name': 'features.card.data.dmeData.identification.name',
            'Contact': 'features.card.data.dmeData.identification.contact',
            'Location': 'features.card.data.dmeData.identification.location'
        }
    },
    'date': {
        'name': 'Date',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'TimeZone': 'features.date.data.dmeData.timeZone',
            'NtpEnabled': 'features.date.data.dmeData.ntp.enabled',
            'NtpFromDhcp': 'features.date.data.dmeData.ntp.getServersFromDhcp',
            'PreferredNtpServer': 'features.date.data.dmeData.ntp.servers.preferredServer',
            'AlternateNtpServer': 'features.date.data.dmeData.ntp.servers.alternateServer'
        }
    },
    'email.data.dmeData': {
        'name': 'Email',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap': {
        'name': 'Ldap',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap.data.certificateData': {
        'name': 'LdapCertificates',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap.data.dmeData.profileMapping': {
        'name': 'LdapProfiles',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'measure': {
        'name': 'Measure',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            '': 'features.measure.data.dmeData.periodicity'
        }
    },
    'mqtt.data.certificateData.trustedClient': {
        'name': 'Mqtt',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'network': {
        'name': 'Network',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'password': {
        'name': 'Password',
        'endpoint': '/rest/mbdetnrs/1.0/card/users/password',
        'columns': {
            'IpAddress': 'IpAddress',
            'Username': 'user.username',
            'CurrentPassword': 'user.current_pwd',
            'NewPassword': 'user.new_pwd'
        }
    },'''
    'powerOutagePolicy.data.dmeData': {
        'name': 'PowerOutagePolicy',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },'''
    'remoteuser': {
        'name': 'RemoteUser',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'schedule.data.dmeData': {
        'name': 'Schedule',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'enabled': 'features.schedule.data.dmeData.enabled',
            'recurrance': 'features.schedule.data.dmeData.recurrence',
            'restart': 'features.schedule.data.dmeData.restartTimeStamp',
            'scheduler': 'features.schedule.data.dmeData.scheduler',
            'shutdown': 'features.schedule.data.dmeData.shutdownTimeStamp',
            'version': 'features.schedule.data.version'
        }
    },
    'smtp': {
        'name': 'Smtp',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'SmtpEnabled': 'features.smtp.data.dmeData.enabled',
            'SmtpPort': 'features.smtp.data.dmeData.port',
            'SmtpServer': 'features.smtp.data.dmeData.server',
            'SmtpRequireAuth': 'features.smtp.data.dmeData.requireAuth',
            'SmtpUser': 'features.smtp.data.dmeData.user',
            'SmtpPassword': 'features.smtp.data.dmeData.password',
            'SmtpRequireTls': 'features.smtp.data.dmeData.requireTls',
            'SmtpVerifyTlsCert': 'features.smtp.data.dmeData.verifyTlsCert',
            'SmtpFromAddress': 'features.smtp.data.dmeData.fromAddress'
        }
    },
    'smtp.data.certificateData': {
        'name': 'SnmpCertificates',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp': {
        'name': 'Snmp',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp.data.dmeData.v3.users': {
        'name': 'SnmpV3Users',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp.data.dmeData.traps.receivers': {
        'name': 'TrapReceivers',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'webserver': {
        'name': 'Webserver',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'HttpsEnabled': 'features.webserver.data.dmeData.https.enabled',
            'HttpsPort': 'features.webserver.data.dmeData.https.port'
        }
    }
},
'1.6.6': {
    'accountService': {
        'name': 'Account',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'MinimumPasswordLength': 'features.accountService.data.dmeData.passwordRules.strength.minLength',
            'MinUpperCase': 'features.accountService.data.dmeData.passwordRules.strength.minUpperCase',
            'MinLowerCase': 'features.accountService.data.dmeData.passwordRules.strength.minLowerCase',
            'MinDigit': 'features.accountService.data.dmeData.passwordRules.strength.minDigit',
            'MinSpecialCharacter': 'features.accountService.data.dmeData.passwordRules.strength.minSpecialCharacter',
            'ExpirationEnabled': 'features.accountService.data.dmeData.passwordRules.expiration.enabled',
            'ExpiresAfterDays': 'features.accountService.data.dmeData.passwordRules.expiration.afterDays',
            'DefaultAccountNeverExpires': 'features.accountService.data.dmeData.passwordRules.expiration.defaultAccountNeverExpires',
            'LockoutRulesEnabled': 'features.accountService.data.dmeData.lockoutRules.enabled',
            'Threshold': 'features.accountService.data.dmeData.lockoutRules.threshold',
            'DefaultAccountNeverBlocks': 'features.accountService.data.dmeData.lockoutRules.defaultAccountNeverBlocks',
        }
    },
    'accountService.data.dmeData.PredefinedAccounts': {
        'name': 'PredefinedAccounts',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'Enabled': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.enabled',
            'Username': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.username',
            'PasswordExpired': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.passwordExpired',
            'Locked': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.locked',
            'Profile': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.profile',
            'PlainPassword': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.password.plaintext',
            'CypheredPassword': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.password.cyphered',
            'FullName': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.fullName',
            'Email': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.email',
            'Phone': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.phone',
            'Organization': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.organization',
            'NotifyByMail': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.notifyByMail',
            'LicenseAgreed': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.licenseAgreed',
            'Language': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.language',
            'DateFormat': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.dateFormat',
            'TimeFormat': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.timeFormat',
            'TemperatureUnit': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.temperatureUnit',
        }
    },
    'card': {
        'name': 'Card',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'Name': 'features.card.data.dmeData.identification.name',
            'Contact': 'features.card.data.dmeData.identification.contact',
            'Location': 'features.card.data.dmeData.identification.location'
        }
    },
    'date': {
        'name': 'Date',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'TimeZone': 'features.date.data.dmeData.timeZone',
            'NtpEnabled': 'features.date.data.dmeData.ntp.enabled',
            'NtpFromDhcp': 'features.date.data.dmeData.ntp.getServersFromDhcp',
            'PreferredNtpServer': 'features.date.data.dmeData.ntp.servers.preferredServer',
            'AlternateNtpServer': 'features.date.data.dmeData.ntp.servers.alternateServer'
        }
    },
    'email.data.dmeData': {
        'name': 'Email',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap': {
        'name': 'Ldap',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap.data.certificateData': {
        'name': 'LdapCertificates',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap.data.dmeData.profileMapping': {
        'name': 'LdapProfiles',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'measure': {
        'name': 'Measure',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            '': 'features.measure.data.dmeData.periodicity'
        }
    },
    'mqtt.data.certificateData.trustedClient': {
        'name': 'Mqtt',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'network': {
        'name': 'Network',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },'''
    'powerOutagePolicy.data.dmeData': {
        'name': 'PowerOutagePolicy',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },'''
    'remoteuser': {
        'name': 'RemoteUser',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'schedule.data.dmeData': {
        'name': 'Schedule',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'enabled': 'features.schedule.data.dmeData.enabled',
            'recurrance': 'features.schedule.data.dmeData.recurrence',
            'restart': 'features.schedule.data.dmeData.restartTimeStamp',
            'scheduler': 'features.schedule.data.dmeData.scheduler',
            'shutdown': 'features.schedule.data.dmeData.shutdownTimeStamp',
            'version': 'features.schedule.data.version'
        }
    },
    'smtp': {
        'name': 'Smtp',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'SmtpEnabled': 'features.smtp.data.dmeData.enabled',
            'SmtpPort': 'features.smtp.data.dmeData.port',
            'SmtpServer': 'features.smtp.data.dmeData.server',
            'SmtpRequireAuth': 'features.smtp.data.dmeData.requireAuth',
            'SmtpUser': 'features.smtp.data.dmeData.user',
            'SmtpPlainPassword': 'features.smtp.data.dmeData.password.plaintext',
            'SmtpCypheredPassword': 'features.smtp.data.dmeData.password.cyphered',
            'SmtpRequireTls': 'features.smtp.data.dmeData.requireTls',
            'SmtpVerifyTlsCert': 'features.smtp.data.dmeData.verifyTlsCert',
            'SmtpFromAddress': 'features.smtp.data.dmeData.fromAddress'
        }
    },
    'smtp.data.certificateData': {
        'name': 'SnmpCertificates',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp': {
        'name': 'Snmp',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp.data.dmeData.v3.users': {
        'name': 'SnmpV3Users',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp.data.dmeData.traps.receivers': {
        'name': 'TrapReceivers',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'webserver': {
        'name': 'Webserver',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'HttpsEnabled': 'features.webserver.data.dmeData.https.enabled',
            'HttpsPort': 'features.webserver.data.dmeData.https.port'
        }
    }
},
'1.7.4': {
    'accountService': {
        'name': 'Account',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'MinimumPasswordLength': 'features.accountService.data.dmeData.passwordRules.strength.minLength',
            'MinUpperCase': 'features.accountService.data.dmeData.passwordRules.strength.minUpperCase',
            'MinLowerCase': 'features.accountService.data.dmeData.passwordRules.strength.minLowerCase',
            'MinDigit': 'features.accountService.data.dmeData.passwordRules.strength.minDigit',
            'MinSpecialCharacter': 'features.accountService.data.dmeData.passwordRules.strength.minSpecialCharacter',
            'ExpirationEnabled': 'features.accountService.data.dmeData.passwordRules.expiration.enabled',
            'ExpiresAfterDays': 'features.accountService.data.dmeData.passwordRules.expiration.afterDays',
            'DefaultAccountNeverExpires': 'features.accountService.data.dmeData.passwordRules.expiration.defaultAccountNeverExpires',
            'LockoutRulesEnabled': 'features.accountService.data.dmeData.lockoutRules.enabled',
            'Threshold': 'features.accountService.data.dmeData.lockoutRules.threshold',
            'DefaultAccountNeverBlocks': 'features.accountService.data.dmeData.lockoutRules.defaultAccountNeverBlocks',
        }
    },
    'accountService.data.dmeData.PredefinedAccounts': {
        'name': 'PredefinedAccounts',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'Enabled': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.enabled',
            'Username': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.username',
            'PasswordExpired': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.passwordExpired',
            'Locked': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.locked',
            'Profile': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.profile',
            'PlainPassword': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.password.plaintext',
            'CypheredPassword': 'features.accountService.data.dmeData.PredefinedAccounts.credentials.password.cyphered',
            'FullName': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.fullName',
            'Email': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.email',
            'Phone': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.phone',
            'Organization': 'features.accountService.data.dmeData.PredefinedAccounts.vCard.organization',
            'NotifyByMail': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.notifyByMail',
            'LicenseAgreed': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.licenseAgreed',
            'Language': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.language',
            'DateFormat': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.dateFormat',
            'TimeFormat': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.timeFormat',
            'TemperatureUnit': 'features.accountService.data.dmeData.PredefinedAccounts.preferences.temperatureUnit',
        }
    },
    'card': {
        'name': 'Card',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'Name': 'features.card.data.dmeData.identification.name',
            'Contact': 'features.card.data.dmeData.identification.contact',
            'Location': 'features.card.data.dmeData.identification.location'
        }
    },
    'date': {
        'name': 'Date',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'TimeZone': 'features.date.data.dmeData.timeZone',
            'NtpEnabled': 'features.date.data.dmeData.ntp.enabled',
            'NtpFromDhcp': 'features.date.data.dmeData.ntp.getServersFromDhcp',
            'PreferredNtpServer': 'features.date.data.dmeData.ntp.servers.preferredServer',
            'AlternateNtpServer': 'features.date.data.dmeData.ntp.servers.alternateServer'
        }
    },
    'email.data.dmeData': {
        'name': 'Email',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap': {
        'name': 'Ldap',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap.data.certificateData': {
        'name': 'LdapCertificates',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'ldap.data.dmeData.profileMapping': {
        'name': 'LdapProfiles',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'measure': {
        'name': 'Measure',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            '': 'features.measure.data.dmeData.periodicity'
        }
    },
    'mqtt.data.certificateData.trustedClient': {
        'name': 'Mqtt',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'network': {
        'name': 'Network',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },'''
    'powerOutagePolicy.data.dmeData': {
        'name': 'PowerOutagePolicy',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },'''
    'remoteuser': {
        'name': 'RemoteUser',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'schedule.data.dmeData': {
        'name': 'Schedule',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'enabled': 'features.schedule.data.dmeData.enabled',
            'recurrance': 'features.schedule.data.dmeData.recurrence',
            'restart': 'features.schedule.data.dmeData.restartTimeStamp',
            'scheduler': 'features.schedule.data.dmeData.scheduler',
            'shutdown': 'features.schedule.data.dmeData.shutdownTimeStamp',
            'version': 'features.schedule.data.version'
        }
    },
    'smtp': {
        'name': 'Smtp',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'SmtpEnabled': 'features.smtp.data.dmeData.enabled',
            'SmtpPort': 'features.smtp.data.dmeData.port',
            'SmtpServer': 'features.smtp.data.dmeData.server',
            'SmtpRequireAuth': 'features.smtp.data.dmeData.requireAuth',
            'SmtpUser': 'features.smtp.data.dmeData.user',
            'SmtpPlainPassword': 'features.smtp.data.dmeData.password.plaintext',
            'SmtpCypheredPassword': 'features.smtp.data.dmeData.password.cyphered',
            'SmtpRequireTls': 'features.smtp.data.dmeData.requireTls',
            'SmtpVerifyTlsCert': 'features.smtp.data.dmeData.verifyTlsCert',
            'SmtpFromAddress': 'features.smtp.data.dmeData.fromAddress'
        }
    },
    'smtp.data.certificateData': {
        'name': 'SnmpCertificates',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp': {
        'name': 'Snmp',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp.data.dmeData.v3.users': {
        'name': 'SnmpV3Users',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'snmp.data.dmeData.traps.receivers': {
        'name': 'TrapReceivers',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {}
    },
    'webserver': {
        'name': 'Webserver',
        'endpoint': '/rest/mbdetnrs/1.0/managers/1/actions/restoreSettings',
        'columns': {
            'HttpsEnabled': 'features.webserver.data.dmeData.https.enabled',
            'HttpsPort': 'features.webserver.data.dmeData.https.port'
        }
    }
}
}