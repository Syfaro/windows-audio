//! Pushed information on audio device and session changes.

use crossbeam_channel::Sender;
use windows::{Guid, IUnknown, Interface, RawPtr, HRESULT};

use bindings::Windows::Win32::Foundation::{BOOL, E_NOINTERFACE, PWSTR, S_OK};
use bindings::Windows::Win32::Media::Audio::CoreAudio::{
    eCapture, eCommunications, eConsole, eMultimedia, eRender, AudioSessionDisconnectReason,
    AudioSessionState, AudioSessionStateActive, AudioSessionStateExpired,
    AudioSessionStateInactive, DisconnectReasonDeviceRemoval,
    DisconnectReasonExclusiveModeOverride, DisconnectReasonFormatChanged,
    DisconnectReasonServerShutdown, DisconnectReasonSessionDisconnected,
    DisconnectReasonSessionLogoff, EDataFlow, ERole, IAudioEndpointVolumeCallback,
    IAudioEndpointVolumeCallback_abi, IAudioSessionControl, IAudioSessionControl2,
    IAudioSessionEvents, IAudioSessionEvents_abi, IAudioSessionNotification,
    IAudioSessionNotification_abi, IMMNotificationClient, IMMNotificationClient_abi,
    AUDIO_VOLUME_NOTIFICATION_DATA, DEVICE_STATE_ACTIVE, DEVICE_STATE_DISABLED,
    DEVICE_STATE_NOTPRESENT, DEVICE_STATE_UNPLUGGED,
};
use bindings::Windows::Win32::System::PropertiesSystem::PROPERTYKEY;

/// Direction in which audio is moving.
#[derive(Debug)]
pub enum FlowDirection {
    /// Audio is being rendered (played).
    Render,
    /// Audio is being captured.
    Capture,
}

/// Audio device role.
#[derive(Debug)]
pub enum Role {
    /// Interaction with the computer.
    Console,
    /// Playing or recording audio content.
    Multimedia,
    /// Voice communications with another person.
    Communications,
}

/// State of the device.
#[derive(Debug)]
pub enum DeviceState {
    /// The audio endpoint device is active. That is, the audio adapter that
    /// connects to the endpoint device is present and enabled. In addition, if
    /// the endpoint device plugs into a jack on the adapter, then the endpoint
    /// device is plugged in.
    Active,
    /// The audio endpoint device is disabled. The user has disabled the device
    /// in the Windows multimedia control panel.
    Disabled,
    /// The audio endpoint device is not present because the audio adapter that
    /// connects to the endpoint device has been removed from the system, or the
    /// user has disabled the adapter device in Device Manager.
    NotPresent,
    /// The audio endpoint device is unplugged. The audio adapter that contains
    /// the jack for the endpoint device is present and enabled, but the
    /// endpoint device is not plugged into the jack. Only a device with
    /// jack-presence detection can be in this state.
    Unplugged,
}

/// A notification about a device change.
#[derive(Debug)]
pub enum DeviceNotification {
    /// The default device has changed.
    DefaultDeviceChanged {
        /// The flow of the device.
        flow_direction: FlowDirection,
        /// The role of the device.
        role: Role,
        /// The device ID.
        default_device_id: String,
    },
    /// A device was added.
    DeviceAdded {
        /// The device ID.
        device_id: String,
    },
    /// A device was removed.
    DeviceRemoved {
        /// The device ID.
        device_id: String,
    },
    /// The state of a device changed.
    StateChanged {
        /// The device ID.
        device_id: String,
        /// The new device state.
        state: DeviceState,
    },
    /// A property changed on the device.
    PropertyChanged {
        /// The device ID.
        device_id: String,
        /// The property fmtid.
        property_key_fmtid: Guid,
        /// The property pid.
        property_key_pid: u32,
    },
}

#[repr(C)]
pub(crate) struct DeviceNotifications {
    _abi: Box<IMMNotificationClient_abi>,
    ref_cnt: u32,
    tx: Sender<DeviceNotification>,
}

impl DeviceNotifications {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(tx: Sender<DeviceNotification>) -> IMMNotificationClient {
        let target = Box::new(Self {
            _abi: Box::new(IMMNotificationClient_abi(
                Self::_query_interface,
                Self::_add_ref,
                Self::_release,
                Self::_on_device_state_changed,
                Self::_on_device_added,
                Self::_on_device_removed,
                Self::_on_default_device_changed,
                Self::_on_property_value_changed,
            )),
            ref_cnt: 1,
            tx,
        });

        unsafe {
            let ptr = Box::into_raw(target);
            std::mem::transmute(ptr)
        }
    }

    fn query_interface(&mut self, iid: &Guid, interface: *mut RawPtr) -> HRESULT {
        if iid == &IAudioSessionEvents::IID || iid == &IUnknown::IID {
            unsafe {
                *interface = self as *mut Self as *mut _;
            }

            self.add_ref();

            S_OK
        } else {
            E_NOINTERFACE
        }
    }

    fn add_ref(&mut self) -> u32 {
        self.ref_cnt += 1;
        self.ref_cnt
    }

    fn release(&mut self) -> u32 {
        self.ref_cnt -= 1;

        if self.ref_cnt == 0 {
            unsafe {
                Box::from_raw(self as *mut Self);
            }
        }

        self.ref_cnt
    }

    fn on_default_device_changed(
        &mut self,
        flow_direction: FlowDirection,
        role: Role,
        default_device_id: String,
    ) {
        self.tx
            .send(DeviceNotification::DefaultDeviceChanged {
                flow_direction,
                role,
                default_device_id,
            })
            .expect("could not send on_default_device_changed");
    }

    fn on_device_added(&mut self, device_id: String) {
        self.tx
            .send(DeviceNotification::DeviceAdded { device_id })
            .expect("could not send on_device_added");
    }

    fn on_device_removed(&mut self, device_id: String) {
        self.tx
            .send(DeviceNotification::DeviceRemoved { device_id })
            .expect("could not send on_device_removed");
    }

    fn on_device_state_changed(&mut self, device_id: String, new_state: DeviceState) {
        self.tx
            .send(DeviceNotification::StateChanged {
                device_id,
                state: new_state,
            })
            .expect("could not send on_device_state_changed");
    }

    fn on_property_value_changed(&mut self, device_id: String, property_key: PROPERTYKEY) {
        self.tx
            .send(DeviceNotification::PropertyChanged {
                device_id,
                property_key_fmtid: property_key.fmtid,
                property_key_pid: property_key.pid,
            })
            .expect("could not send on_property_value_changed");
    }
}

impl DeviceNotifications {
    unsafe extern "system" fn _query_interface(
        this: RawPtr,
        iid: &Guid,
        interface: *mut RawPtr,
    ) -> HRESULT {
        (*(this as *mut Self)).query_interface(iid, interface)
    }

    unsafe extern "system" fn _add_ref(this: RawPtr) -> u32 {
        (*(this as *mut Self)).add_ref()
    }

    unsafe extern "system" fn _release(this: RawPtr) -> u32 {
        (*(this as *mut Self)).release()
    }

    unsafe extern "system" fn _on_default_device_changed(
        this: RawPtr,
        flow: EDataFlow,
        role: ERole,
        default_device_id: PWSTR,
    ) -> HRESULT {
        let default_device_id = crate::pwstr_to_string(default_device_id);
        tracing::trace!(
            "got on_default_device_changed: flow = {:?}, role = {:?}, default_device_id = {}",
            flow,
            role,
            default_device_id
        );

        #[allow(non_upper_case_globals)]
        let flow = match flow {
            eRender => FlowDirection::Render,
            eCapture => FlowDirection::Capture,
            _ => {
                tracing::warn!("got unknown flow direction {:?}", flow);
                return S_OK;
            }
        };

        #[allow(non_upper_case_globals)]
        let role = match role {
            eConsole => Role::Console,
            eMultimedia => Role::Multimedia,
            eCommunications => Role::Communications,
            _ => {
                tracing::warn!("got unknown role {:?}", role);
                return S_OK;
            }
        };

        (*(this as *mut Self)).on_default_device_changed(flow, role, default_device_id);

        S_OK
    }

    unsafe extern "system" fn _on_device_added(this: RawPtr, device_id: PWSTR) -> HRESULT {
        let device_id = crate::pwstr_to_string(device_id);
        tracing::trace!("got on_device_added: device_id = {}", device_id);

        (*(this as *mut Self)).on_device_added(device_id);

        S_OK
    }

    unsafe extern "system" fn _on_device_removed(this: RawPtr, device_id: PWSTR) -> HRESULT {
        let device_id = crate::pwstr_to_string(device_id);
        tracing::trace!("got on_device_removed: device_id = {}", device_id);

        (*(this as *mut Self)).on_device_removed(device_id);

        S_OK
    }

    unsafe extern "system" fn _on_device_state_changed(
        this: RawPtr,
        device_id: PWSTR,
        new_state: u32,
    ) -> HRESULT {
        let device_id = crate::pwstr_to_string(device_id);
        tracing::trace!("got on_device_state_changed: device_id = {}", device_id);

        let new_state = match new_state {
            DEVICE_STATE_ACTIVE => DeviceState::Active,
            DEVICE_STATE_DISABLED => DeviceState::Disabled,
            DEVICE_STATE_NOTPRESENT => DeviceState::NotPresent,
            DEVICE_STATE_UNPLUGGED => DeviceState::Unplugged,
            _ => {
                tracing::warn!("got unknown device state: {:?}", new_state);
                return S_OK;
            }
        };

        (*(this as *mut Self)).on_device_state_changed(device_id, new_state);

        S_OK
    }

    unsafe extern "system" fn _on_property_value_changed(
        this: RawPtr,
        device_id: PWSTR,
        property_key: PROPERTYKEY,
    ) -> HRESULT {
        let device_id = crate::pwstr_to_string(device_id);
        tracing::trace!("got on_property_value_changed: device_id = {}, propertykey fmtid = {:?}, propertykey pid = {}", device_id, property_key.fmtid, property_key.pid);

        (*(this as *mut Self)).on_property_value_changed(device_id, property_key);

        S_OK
    }
}

/// An event for a device.
#[derive(Debug)]
pub struct DeviceEvent {
    /// The new volume level, [0, 1].
    pub level: f32,
    /// If the device is muted.
    pub muted: bool,

    /// The volume for each channel.
    pub channel_volumes: Vec<f32>,

    /// An event context, if one exists.
    pub event_context: Guid,
}

impl From<AUDIO_VOLUME_NOTIFICATION_DATA> for DeviceEvent {
    fn from(notification_data: AUDIO_VOLUME_NOTIFICATION_DATA) -> Self {
        let channel_volumes = unsafe {
            std::slice::from_raw_parts(
                &notification_data.afChannelVolumes as *const _,
                notification_data.nChannels as usize,
            )
        };

        Self {
            level: notification_data.fMasterVolume,
            muted: notification_data.bMuted.into(),

            channel_volumes: channel_volumes.to_vec(),

            event_context: notification_data.guidEventContext,
        }
    }
}

#[repr(C)]
pub(crate) struct DeviceEvents {
    _abi: Box<IAudioEndpointVolumeCallback_abi>,
    ref_cnt: u32,
    tx: Sender<DeviceEvent>,
}

impl DeviceEvents {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(tx: Sender<DeviceEvent>) -> IAudioEndpointVolumeCallback {
        let target = Box::new(Self {
            _abi: Box::new(IAudioEndpointVolumeCallback_abi(
                Self::_query_interface,
                Self::_add_ref,
                Self::_release,
                Self::_on_notify,
            )),
            ref_cnt: 1,
            tx,
        });

        unsafe {
            let ptr = Box::into_raw(target);
            std::mem::transmute(ptr)
        }
    }

    fn query_interface(&mut self, iid: &Guid, interface: *mut RawPtr) -> HRESULT {
        if iid == &IAudioSessionEvents::IID || iid == &IUnknown::IID {
            unsafe {
                *interface = self as *mut Self as *mut _;
            }

            self.add_ref();

            S_OK
        } else {
            E_NOINTERFACE
        }
    }

    fn add_ref(&mut self) -> u32 {
        self.ref_cnt += 1;
        self.ref_cnt
    }

    fn release(&mut self) -> u32 {
        self.ref_cnt -= 1;

        if self.ref_cnt == 0 {
            unsafe {
                Box::from_raw(self as *mut Self);
            }
        }

        self.ref_cnt
    }

    fn on_notify(&mut self, device_event: DeviceEvent) {
        self.tx
            .send(device_event)
            .expect("could not send on_notify");
    }
}

impl DeviceEvents {
    unsafe extern "system" fn _query_interface(
        this: RawPtr,
        iid: &Guid,
        interface: *mut RawPtr,
    ) -> HRESULT {
        (*(this as *mut Self)).query_interface(iid, interface)
    }

    unsafe extern "system" fn _add_ref(this: RawPtr) -> u32 {
        (*(this as *mut Self)).add_ref()
    }

    unsafe extern "system" fn _release(this: RawPtr) -> u32 {
        (*(this as *mut Self)).release()
    }

    unsafe extern "system" fn _on_notify(
        this: RawPtr,
        pnotify: *mut AUDIO_VOLUME_NOTIFICATION_DATA,
    ) -> HRESULT {
        let device_event = DeviceEvent::from(*pnotify);
        tracing::trace!("got on_notify: device_event = {:?}", device_event);

        (*(this as *mut Self)).on_notify(device_event);

        S_OK
    }
}

/// A notification about an audio session.
#[derive(Debug)]
pub struct AudioSessionNotification {
    /// The session identifier.
    pub session_identifier: String,
    /// The session instance identifier.
    pub session_instance_identifier: String,
}

#[repr(C)]
pub(crate) struct AudioSessionNotifications {
    _abi: Box<IAudioSessionNotification_abi>,
    ref_cnt: u32,
    tx: Sender<AudioSessionNotification>,
}

impl AudioSessionNotifications {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(tx: Sender<AudioSessionNotification>) -> IAudioSessionNotification {
        let target = Box::new(Self {
            _abi: Box::new(IAudioSessionNotification_abi(
                Self::_query_interface,
                Self::_add_ref,
                Self::_release,
                Self::_on_session_created,
            )),
            ref_cnt: 1,
            tx,
        });

        unsafe {
            let ptr = Box::into_raw(target);
            std::mem::transmute(ptr)
        }
    }

    fn query_interface(&mut self, iid: &Guid, interface: *mut RawPtr) -> HRESULT {
        if iid == &IAudioSessionEvents::IID || iid == &IUnknown::IID {
            unsafe {
                *interface = self as *mut Self as *mut _;
            }

            self.add_ref();

            S_OK
        } else {
            E_NOINTERFACE
        }
    }

    fn add_ref(&mut self) -> u32 {
        self.ref_cnt += 1;
        self.ref_cnt
    }

    fn release(&mut self) -> u32 {
        self.ref_cnt -= 1;

        if self.ref_cnt == 0 {
            unsafe {
                Box::from_raw(self as *mut Self);
            }
        }

        self.ref_cnt
    }

    fn on_session_created(&mut self, new_session: IAudioSessionControl2) {
        let (session_identifier, session_instance_identifier) = unsafe {
            let session_identifier = new_session.GetSessionIdentifier().unwrap_or_default();
            let session_identifier = crate::pwstr_to_string(session_identifier);

            let session_instance_identifier = new_session
                .GetSessionInstanceIdentifier()
                .unwrap_or_default();
            let session_instance_identifier = crate::pwstr_to_string(session_instance_identifier);

            (session_identifier, session_instance_identifier)
        };

        self.tx
            .send(AudioSessionNotification {
                session_identifier,
                session_instance_identifier,
            })
            .expect("could not send on_session_created");
    }
}

impl AudioSessionNotifications {
    unsafe extern "system" fn _query_interface(
        this: RawPtr,
        iid: &Guid,
        interface: *mut RawPtr,
    ) -> HRESULT {
        (*(this as *mut Self)).query_interface(iid, interface)
    }

    unsafe extern "system" fn _add_ref(this: RawPtr) -> u32 {
        (*(this as *mut Self)).add_ref()
    }

    unsafe extern "system" fn _release(this: RawPtr) -> u32 {
        (*(this as *mut Self)).release()
    }

    unsafe extern "system" fn _on_session_created(this: RawPtr, new_session: RawPtr) -> HRESULT {
        tracing::trace!("got on_session_created");

        struct ComObject(RawPtr);
        let obj = ComObject(new_session);
        let sess = (&*(&obj as *const _ as *const IAudioSessionControl)).clone();

        let new_session = if let Ok(control) = sess.cast() {
            control
        } else {
            tracing::warn!("could not cast NewSession to IAudioSessionControl2");
            return S_OK;
        };

        (*(this as *mut Self)).on_session_created(new_session);

        S_OK
    }
}

/// The type of change for an audio session.
#[derive(Debug)]
pub enum AudioSessionEvent {
    /// The volume or mute status has changed.
    VolumeChange {
        /// The new volume level, [0, 1].
        level: f32,
        /// If the session is muted.
        muted: bool,
    },
    /// The state of the session has changed.
    StateChange(SessionState),
    /// The session has disconnected.
    Disconnect(SessionDisconnect),
}

/// An audio session state.
#[derive(Debug)]
pub enum SessionState {
    /// The audio session is currently active.
    Active,
    /// The audio session has become inactive.
    Inactive,
    /// The audio session has expired and is no longer valid.
    Expired,
}

/// The reason why an audio session disconnected.
#[derive(Debug)]
pub enum SessionDisconnect {
    /// The user removed the audio endpoint device.
    DeviceRemoved,
    /// The Windows audio service has stopped.
    ServerShutdown,
    /// The stream format changed for the device that the audio session is
    /// connected to.
    FormatChanged,
    /// The user logged off the Windows Terminal Services (WTS) session that the
    /// audio session was running in.
    SessionLogoff,
    /// The WTS session that the audio session was running in was disconnected.
    SessionDisconnected,
    /// The (shared-mode) audio session was disconnected to make the audio
    /// endpoint device available for an exclusive-mode connection.
    ExclusiveModeOverride,
}

#[repr(C)]
pub(crate) struct AudioSessionEvents {
    _abi: Box<IAudioSessionEvents_abi>,
    ref_cnt: u32,

    tx: Sender<AudioSessionEvent>,
}

/// Our code for handling audio session events.
impl AudioSessionEvents {
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(tx: Sender<AudioSessionEvent>) -> IAudioSessionEvents {
        let target = Box::new(Self {
            _abi: Box::new(IAudioSessionEvents_abi(
                Self::_query_interface,
                Self::_add_ref,
                Self::_release,
                Self::_on_display_name_changed,
                Self::_on_icon_path_changed,
                Self::_on_simple_volume_changed,
                Self::_on_channel_volume_changed,
                Self::_on_grouping_param_changed,
                Self::_on_state_changed,
                Self::_on_session_disconnected,
            )),
            ref_cnt: 1,
            tx,
        });

        unsafe {
            let ptr = Box::into_raw(target);
            std::mem::transmute(ptr)
        }
    }

    fn query_interface(&mut self, iid: &Guid, interface: *mut RawPtr) -> HRESULT {
        if iid == &IAudioSessionEvents::IID || iid == &IUnknown::IID {
            unsafe {
                *interface = self as *mut Self as *mut _;
            }

            self.add_ref();

            S_OK
        } else {
            E_NOINTERFACE
        }
    }

    fn add_ref(&mut self) -> u32 {
        self.ref_cnt += 1;
        self.ref_cnt
    }

    fn release(&mut self) -> u32 {
        self.ref_cnt -= 1;

        if self.ref_cnt == 0 {
            unsafe {
                Box::from_raw(self as *mut Self);
            }
        }

        self.ref_cnt
    }

    fn simple_volume_changed(&mut self, new_volume: f32, new_mute: bool) {
        self.tx
            .send(AudioSessionEvent::VolumeChange {
                level: new_volume,
                muted: new_mute,
            })
            .expect("could not send simple_volume_changed");
    }

    fn on_state_changed(&mut self, state: SessionState) {
        self.tx
            .send(AudioSessionEvent::StateChange(state))
            .expect("could not send on_state_changed");
    }

    fn on_session_disconnected(&mut self, session_disconnect: SessionDisconnect) {
        self.tx
            .send(AudioSessionEvent::Disconnect(session_disconnect))
            .expect("could not send on_session_disconnected");
    }
}

/// Methods called by Windows API.
impl AudioSessionEvents {
    unsafe extern "system" fn _query_interface(
        this: RawPtr,
        iid: &Guid,
        interface: *mut RawPtr,
    ) -> HRESULT {
        (*(this as *mut Self)).query_interface(iid, interface)
    }

    unsafe extern "system" fn _add_ref(this: RawPtr) -> u32 {
        (*(this as *mut Self)).add_ref()
    }

    unsafe extern "system" fn _release(this: RawPtr) -> u32 {
        (*(this as *mut Self)).release()
    }

    unsafe extern "system" fn _on_display_name_changed(
        _this: RawPtr,
        _new_display_name: PWSTR,
        _event_context: *const Guid,
    ) -> HRESULT {
        tracing::trace!("on_display_name_changed");

        S_OK
    }

    unsafe extern "system" fn _on_icon_path_changed(
        _this: RawPtr,
        _new_icon_path: PWSTR,
        _event_context: *const Guid,
    ) -> HRESULT {
        tracing::trace!("on_icon_path_changed");

        S_OK
    }

    unsafe extern "system" fn _on_simple_volume_changed(
        this: RawPtr,
        new_volume: f32,
        new_mute: BOOL,
        _event_context: *const Guid,
    ) -> HRESULT {
        tracing::trace!(
            "on_simple_volume_changed: new_volume = {}, new_mute = {}",
            new_volume,
            bool::from(new_mute)
        );

        (*(this as *mut Self)).simple_volume_changed(new_volume, new_mute.into());

        S_OK
    }

    unsafe extern "system" fn _on_channel_volume_changed(
        _this: RawPtr,
        _channel_count: u32,
        _new_channel_volume_array: *mut f32,
        _changed_channel: u32,
        _event_context: *const Guid,
    ) -> HRESULT {
        tracing::trace!("on_channel_volume_changed");

        S_OK
    }

    unsafe extern "system" fn _on_grouping_param_changed(
        _this: RawPtr,
        _new_grouping_param: *const Guid,
        _event_context: *const Guid,
    ) -> HRESULT {
        tracing::trace!("on_grouping_param_changed");

        S_OK
    }

    unsafe extern "system" fn _on_state_changed(
        this: RawPtr,
        new_state: AudioSessionState,
    ) -> HRESULT {
        tracing::trace!("on_state_changed: new_state = {:?}", new_state);

        #[allow(non_upper_case_globals)]
        let state = match new_state {
            AudioSessionStateActive => SessionState::Active,
            AudioSessionStateInactive => SessionState::Inactive,
            AudioSessionStateExpired => SessionState::Expired,
            _ => {
                tracing::warn!("got unknown state");
                return S_OK;
            }
        };

        (*(this as *mut Self)).on_state_changed(state);

        S_OK
    }

    unsafe extern "system" fn _on_session_disconnected(
        this: RawPtr,
        disconnect_reason: AudioSessionDisconnectReason,
    ) -> HRESULT {
        tracing::trace!(
            "on_session_disconnected: disconnect_reason = {:?}",
            disconnect_reason
        );

        #[allow(non_upper_case_globals)]
        let session_disconnect = match disconnect_reason {
            DisconnectReasonDeviceRemoval => SessionDisconnect::DeviceRemoved,
            DisconnectReasonServerShutdown => SessionDisconnect::ServerShutdown,
            DisconnectReasonFormatChanged => SessionDisconnect::FormatChanged,
            DisconnectReasonSessionLogoff => SessionDisconnect::SessionLogoff,
            DisconnectReasonSessionDisconnected => SessionDisconnect::SessionDisconnected,
            DisconnectReasonExclusiveModeOverride => SessionDisconnect::ExclusiveModeOverride,
            _ => {
                tracing::warn!("got unknown disconnect reason");
                return S_OK;
            }
        };

        (*(this as *mut Self)).on_session_disconnected(session_disconnect);

        S_OK
    }
}
