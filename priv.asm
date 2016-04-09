            SECTION     privileges
PrivTable:
            SECTION     rights
RightsTable:


%macro      priv        1
            SECTION     .data
%%len:      db          %%eostr-%%str
%%str:      db          %1
%%eostr:
            SECTION     privileges
            dd          %%len
            __SECT__
%endmacro

%macro      endtab      1
            SECTION     %1
            dd          0
            __SECT__
%endmacro

%macro      right       1
            SECTION     .data
%%len:      db          %%eostr-%%str
%%str:      db          %1
%%eostr:
            SECTION     rights
            dd          %%len
            __SECT__
%endmacro


            SECTION     .data
            priv        'AssignPrimaryToken'
            priv        'Audit'
            priv        'Backup'
            priv        'ChangeNotify'
            priv        'CreateGlobal'
            priv        'CreatePagefile'
            priv        'CreatePermanent'
            priv        'CreateSymbolicLink'
            priv        'CreateToken'
            priv        'Debug'
            priv        'EnableDelegation'
            priv        'Impersonate'
            priv        'IncreaseBasePriority'
            priv        'IncreaseQuota'
            priv        'IncreaseWorkingSet'
            priv        'LoadDriver'
            priv        'LockMemory'
            priv        'MachineAccount'
            priv        'ManageVolume'
            priv        'ProfileSingleProcess'
            priv        'Relabel'
            priv        'RemoteShutdown'
            priv        'Restore'
            priv        'Security'
            priv        'Shutdown'
            priv        'SyncAgent'
            priv        'SystemEnvironment'
            priv        'SystemProfile'
            priv        'Systemtime'
            priv        'TakeOwnership'
            priv        'Tcb'
            priv        'TimeZone'
            priv        'TrustedCredManAccess'
            priv        'Undock'
            priv        'UnsolicitedInput'
            endtab      privileges

            right       'BatchLogon'
            right       'DenyBatchLogon'
            right       'DenyInteractiveLogon'
            right       'DenyNetworkLogon'
            right       'DenyRemoteInteractiveLogon'
            right       'InteractiveLogon'
            right       'RemoteInteractiveLogon'
            right       'ServiceLogon'
            endtab      rights
