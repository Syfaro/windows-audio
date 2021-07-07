fn main() {
    windows::build! {
        Windows::Win32::Foundation::*,
        Windows::Win32::Media::Audio::CoreAudio::*,
        Windows::Win32::Storage::StructuredStorage::*,
        Windows::Win32::System::Com::*,
        Windows::Win32::System::ProcessStatus::*,
        Windows::Win32::System::PropertiesSystem::*,
        Windows::Win32::System::SystemServices::*,
        Windows::Win32::System::Threading::*,
    };
}
