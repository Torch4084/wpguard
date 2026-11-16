pub mod access_control;
pub mod crypto;
pub mod files;
pub mod injection;
pub mod php_generic;

use crate::rule::Rule;

/// Every rule that ships with wpguard.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Access control
        Box::new(access_control::UnauthenticatedAjaxAction),
        Box::new(access_control::AuthenticatedAjaxAction),
        Box::new(access_control::OpenRestRoute),
        Box::new(access_control::RestRouteWithoutPermission),
        Box::new(access_control::RestPermissionWithoutCheck),
        Box::new(access_control::WeakAdminCapability),
        Box::new(access_control::AdminPostWithoutCapability),
        // Injection
        Box::new(injection::UnpreparedDatabaseQuery),
        Box::new(injection::UnserializeOfUserInput),
        Box::new(injection::DynamicCodeEvaluation),
        Box::new(injection::DynamicFileInclusion),
        Box::new(injection::UnescapedOutput),
        Box::new(injection::OpenRedirect),
        // Files and network
        Box::new(files::UploadWithoutTypeCheck),
        Box::new(files::RequestControlledUrlFetch),
        // Crypto
        Box::new(crypto::FastHashForPasswords),
        Box::new(crypto::WeakRandomnessForSecrets),
        // Generic PHP
        Box::new(php_generic::CommandExecution),
        Box::new(php_generic::TlsVerificationDisabled),
    ]
}
