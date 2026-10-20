//! Operating system service integration.
//!
//! The node runs unattended: Windows uses the service control manager, Linux
//! uses a systemd unit and macOS uses a launch agent. The module is only
//! built for native targets.

use crate::config::ServiceConfig;
use crate::error::*;
use std::path::PathBuf;
use std::sync::Arc;

/// The state of the installed service.
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    /// Whether the service is installed on this machine.
    pub installed: bool,
    /// Whether the service is running right now.
    pub running: bool,
    /// The service integration of this platform.
    pub kind: &'static str,
}

/// The work that the service performs while it runs.
pub type ServiceAction = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// Install the service so that it starts with the machine.
pub fn install(config: &ServiceConfig) -> Result<ServiceStatus> {
    platform::install(config)
}

/// Remove the service from the machine.
pub fn uninstall(config: &ServiceConfig) -> Result<()> {
    platform::uninstall(config)
}

/// Report the state of the service.
pub fn status(config: &ServiceConfig) -> Result<ServiceStatus> {
    platform::status(config)
}

/// Ask the service to start.
pub fn start(config: &ServiceConfig) -> Result<()> {
    platform::start(config)
}

/// Ask the service to stop.
pub fn stop(config: &ServiceConfig) -> Result<()> {
    platform::stop(config)
}

/// Run the node under the service dispatcher of the platform.
///
/// The action runs the node, the signal tells the node that the service
/// manager asked it to stop.
pub fn run_as_service(
    config: &ServiceConfig,
    action: ServiceAction,
    stop: Arc<tokio::sync::watch::Sender<bool>>,
) -> Result<()> {
    platform::run_as_service(config, action, stop)
}

/// The Windows integration with the service control manager.
#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceErrorControl, ServiceInfo, ServiceStartType,
        ServiceState, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    /// The kind of integration this platform offers.
    const KIND: &str = "windows";

    /// The name of the service in the service control manager.
    fn service_name(config: &ServiceConfig) -> OsString {
        OsString::from(config.name.as_str())
    }

    /// Open the service control manager.
    fn manager() -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))
    }

    /// Open the service control manager for queries.
    fn query_manager() -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::QUERY_STATUS)
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))
    }

    pub fn install(config: &ServiceConfig) -> Result<ServiceStatus> {
        if status(config)?.installed {
            return Err(MxNodeError::Service(ServiceError::AlreadyInstalled));
        }

        let executable = std::env::current_exe()
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

        let info = ServiceInfo {
            name: service_name(config),
            display_name: OsString::from(config.display_name.as_str()),
            service_type: ServiceType::OWN_PROCESS,
            start_type: if config.autostart {
                ServiceStartType::AutoStart
            } else {
                ServiceStartType::DemandStart
            },
            error_control: ServiceErrorControl::Normal,
            executable_path: executable,
            launch_arguments: vec![OsString::from("serve")],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };

        manager()?
            .create_service(&info, ServiceAccess::QUERY_STATUS)
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

        Ok(ServiceStatus {
            installed: true,
            running: false,
            kind: KIND,
        })
    }

    pub fn uninstall(config: &ServiceConfig) -> Result<()> {
        let service = query_manager()?
            .open_service(
                service_name(config),
                ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
            )
            .map_err(|_| MxNodeError::Service(ServiceError::NotInstalled))?;

        service
            .delete()
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))
    }

    pub fn status(config: &ServiceConfig) -> Result<ServiceStatus> {
        let manager = query_manager()?;

        match manager.open_service(service_name(config), ServiceAccess::QUERY_STATUS) {
            Ok(service) => {
                let state = service
                    .query_status()
                    .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

                Ok(ServiceStatus {
                    installed: true,
                    running: state.state == ServiceState::Running,
                    kind: KIND,
                })
            }
            Err(_) => Ok(ServiceStatus {
                installed: false,
                running: false,
                kind: KIND,
            }),
        }
    }

    pub fn start(config: &ServiceConfig) -> Result<()> {
        let service = query_manager()?
            .open_service(
                service_name(config),
                ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|_| MxNodeError::Service(ServiceError::NotInstalled))?;

        service
            .start(&[])
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))
    }

    pub fn stop(config: &ServiceConfig) -> Result<()> {
        let service = query_manager()?
            .open_service(
                service_name(config),
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|_| MxNodeError::Service(ServiceError::NotInstalled))?;

        service
            .stop()
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))
    }

    pub fn run_as_service(
        config: &ServiceConfig,
        action: ServiceAction,
        stop: Arc<tokio::sync::watch::Sender<bool>>,
    ) -> Result<()> {
        use std::sync::OnceLock;

        static ACTION: OnceLock<ServiceAction> = OnceLock::new();
        let _ = ACTION.set(action);

        extern "system" fn service_main(_: u32, _: *mut *mut u16) {
            let Some(action) = ACTION.get() else {
                return;
            };
            if let Err(e) = action() {
                tracing::error!(error = %e, "the service action failed");
            }
        }

        let stop = Arc::clone(&stop);
        service_control_handler::register(config.name.as_str(), move |control| {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = stop.send(true);
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NoError,
            }
        })
        .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

        service_dispatcher::start(config.name.as_str(), service_main)
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))
    }
}

/// The Linux integration with systemd.
#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// The kind of integration this platform offers.
    const KIND: &str = "systemd";

    /// The path of the unit file.
    fn unit_path(config: &ServiceConfig) -> PathBuf {
        let file = format!("{}.service", config.name);
        if config.user_scope {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".config").join("systemd").join("user").join(file)
        } else {
            PathBuf::from("/etc/systemd/system").join(file)
        }
    }

    /// The content of the unit file.
    fn unit_text(config: &ServiceConfig) -> String {
        let executable = std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "mx-node".to_string());
        let wanted_by = if config.user_scope {
            "default.target"
        } else {
            "multi-user.target"
        };

        format!(
            "[Unit]\nDescription={}\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} serve\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy={}\n",
            config.description, executable, wanted_by
        )
    }

    /// Run a systemctl command and return its output.
    fn systemctl(config: &ServiceConfig, args: &[&str]) -> Result<String> {
        let mut command = std::process::Command::new("systemctl");
        if config.user_scope {
            command.arg("--user");
        }
        command.args(args);

        let output = command
            .output()
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn install(config: &ServiceConfig) -> Result<ServiceStatus> {
        if status(config)?.installed {
            return Err(MxNodeError::Service(ServiceError::AlreadyInstalled));
        }

        let path = unit_path(config);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;
        }
        std::fs::write(&path, unit_text(config))
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

        systemctl(config, &["daemon-reload"])?;
        systemctl(config, &["enable", &config.name])?;

        Ok(ServiceStatus {
            installed: true,
            running: false,
            kind: KIND,
        })
    }

    pub fn uninstall(config: &ServiceConfig) -> Result<()> {
        let path = unit_path(config);
        if !path.exists() {
            return Err(MxNodeError::Service(ServiceError::NotInstalled));
        }

        systemctl(config, &["disable", &config.name])?;
        std::fs::remove_file(&path)
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;
        systemctl(config, &["daemon-reload"])?;
        Ok(())
    }

    pub fn status(config: &ServiceConfig) -> Result<ServiceStatus> {
        let installed = unit_path(config).exists();
        let running = if installed {
            systemctl(config, &["is-active", &config.name])
                .map(|state| state == "active")
                .unwrap_or(false)
        } else {
            false
        };

        Ok(ServiceStatus {
            installed,
            running,
            kind: KIND,
        })
    }

    pub fn start(config: &ServiceConfig) -> Result<()> {
        systemctl(config, &["start", &config.name])?;
        Ok(())
    }

    pub fn stop(config: &ServiceConfig) -> Result<()> {
        systemctl(config, &["stop", &config.name])?;
        Ok(())
    }

    pub fn run_as_service(
        _config: &ServiceConfig,
        _action: ServiceAction,
        _stop: Arc<tokio::sync::watch::Sender<bool>>,
    ) -> Result<()> {
        Err(MxNodeError::Service(ServiceError::UnsupportedPlatform(
            "systemd starts the node with the serve command".to_string(),
        )))
    }
}

/// The macOS integration with launchd.
#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    /// The kind of integration this platform offers.
    const KIND: &str = "launchd";

    /// The label of the launch agent.
    fn label(config: &ServiceConfig) -> String {
        format!("com.domail.{}", config.name)
    }

    /// The path of the property list.
    fn plist_path(config: &ServiceConfig) -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{}.plist", label(config)))
    }

    /// The content of the property list.
    fn plist_text(config: &ServiceConfig) -> String {
        let executable = std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "mx-node".to_string());
        let log_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let log_dir = PathBuf::from(log_dir).join(".domail").join("logs");

        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{label}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{executable}</string>\n    <string>serve</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n  <key>StandardOutPath</key>\n  <string>{log}/mx-node.log</string>\n  <key>StandardErrorPath</key>\n  <string>{log}/mx-node.error.log</string>\n</dict>\n</plist>\n",
            label = label(config),
            executable = executable,
            log = log_dir.display()
        )
    }

    /// The identifier of the user that owns the agent.
    fn user_id() -> String {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "501".to_string())
    }

    /// Run a launchctl command.
    fn launchctl(args: &[&str]) -> Result<()> {
        let output = std::process::Command::new("launchctl")
            .args(args)
            .output()
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

        if !output.status.success() {
            return Err(MxNodeError::Service(ServiceError::Failed(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            )));
        }

        Ok(())
    }

    pub fn install(config: &ServiceConfig) -> Result<ServiceStatus> {
        if status(config)?.installed {
            return Err(MxNodeError::Service(ServiceError::AlreadyInstalled));
        }

        let path = plist_path(config);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;
        }
        std::fs::write(&path, plist_text(config))
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;

        let domain = format!("gui/{}", user_id());
        launchctl(&["bootstrap", &domain, &path.to_string_lossy()])?;
        launchctl(&["enable", &format!("{}/{}", domain, label(config))])?;

        Ok(ServiceStatus {
            installed: true,
            running: false,
            kind: KIND,
        })
    }

    pub fn uninstall(config: &ServiceConfig) -> Result<()> {
        let path = plist_path(config);
        if !path.exists() {
            return Err(MxNodeError::Service(ServiceError::NotInstalled));
        }

        let domain = format!("gui/{}", user_id());
        let _ = launchctl(&["bootout", &format!("{}/{}", domain, label(config))]);
        std::fs::remove_file(&path)
            .map_err(|e| MxNodeError::Service(ServiceError::Failed(e.to_string())))?;
        Ok(())
    }

    pub fn status(config: &ServiceConfig) -> Result<ServiceStatus> {
        let installed = plist_path(config).exists();
        let running = if installed {
            std::process::Command::new("launchctl")
                .arg("list")
                .arg(label(config))
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        } else {
            false
        };

        Ok(ServiceStatus {
            installed,
            running,
            kind: KIND,
        })
    }

    pub fn start(config: &ServiceConfig) -> Result<()> {
        let domain = format!("gui/{}", user_id());
        launchctl(&["kickstart", "-k", &format!("{}/{}", domain, label(config))])?;
        Ok(())
    }

    pub fn stop(config: &ServiceConfig) -> Result<()> {
        let domain = format!("gui/{}", user_id());
        launchctl(&["kill", "SIGTERM", &format!("{}/{}", domain, label(config))])?;
        Ok(())
    }

    pub fn run_as_service(
        _config: &ServiceConfig,
        _action: ServiceAction,
        _stop: Arc<tokio::sync::watch::Sender<bool>>,
    ) -> Result<()> {
        Err(MxNodeError::Service(ServiceError::UnsupportedPlatform(
            "launchd starts the node with the serve command".to_string(),
        )))
    }
}

/// The fallback for platforms without a service integration.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use super::*;

    /// The kind of integration this platform offers.
    const KIND: &str = "unsupported";

    /// The error that every operation reports.
    fn unsupported() -> MxNodeError {
        MxNodeError::Service(ServiceError::UnsupportedPlatform(
            "this platform has no service integration".to_string(),
        ))
    }

    pub fn install(_config: &ServiceConfig) -> Result<ServiceStatus> {
        Err(unsupported())
    }

    pub fn uninstall(_config: &ServiceConfig) -> Result<()> {
        Err(unsupported())
    }

    pub fn status(_config: &ServiceConfig) -> Result<ServiceStatus> {
        Ok(ServiceStatus {
            installed: false,
            running: false,
            kind: KIND,
        })
    }

    pub fn start(_config: &ServiceConfig) -> Result<()> {
        Err(unsupported())
    }

    pub fn stop(_config: &ServiceConfig) -> Result<()> {
        Err(unsupported())
    }

    pub fn run_as_service(
        _config: &ServiceConfig,
        _action: ServiceAction,
        _stop: Arc<tokio::sync::watch::Sender<bool>>,
    ) -> Result<()> {
        Err(unsupported())
    }
}