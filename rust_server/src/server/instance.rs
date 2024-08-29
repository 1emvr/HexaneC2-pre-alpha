use rand::Rng;

use crate::return_error;
use crate::server::INSTANCES;
use crate::server::types::Hexane;
use crate::server::utils::wrap_message;
use crate::server::listener::setup_listener;

pub(crate) fn load_instance(args: Vec<String>) -> crate::server::error::Result<()> {
    if args.len() != 3 {
        return_error!(format!("invalid input: {} arguments", args.len()))
    }

    let mut instance = match crate::server::config::map_config(&args[2]) {
        Ok(instance)    => instance,
        Err(e)          =>  return Err(e),
    };

    setup_instance(&mut instance)?;
    setup_listener(&mut instance)?;

    let build_dir   = instance.compiler.build_directory.as_str();
    let name        = instance.builder.output_name.as_str();
    let ext         = instance.compiler.file_extension.as_str();

    wrap_message("info", format!("{}/{}.{} is ready", build_dir, name, ext));
    INSTANCES.lock().unwrap().push(instance);

    Ok(())
}

fn setup_instance(instance: &mut Hexane) -> crate::server::error::Result<()> {
    let mut rng = rand::thread_rng();

    if instance.main.debug {
        instance.compiler.compiler_flags = String::from("-std=c++23 -g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin -Wl,--no-seh,--enable-stdcall-fixup,--gc-sections");
    } else {
        instance.compiler.compiler_flags = String::from("-std=c++23 -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC  -fno-builtin -Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections");
    }

    instance.peer_id = rng.random::<u32>();
    instance.group_id = 0;

    // todo: build process

    Ok(())
}

