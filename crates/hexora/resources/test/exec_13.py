import shutil
import subprocess
import os
import tempfile
import packaging
import logging

logger = logging.getLogger(__name__)

input_file = "input_video.mp4"
tmp_dir = tempfile.mkdtemp()

try:
    local_input = os.path.join(tmp_dir, os.path.basename(input_file))
    shutil.copy2(input_file, local_input)

    base, ext = os.path.splitext(local_input)
    local_output = f"{base}_optimized{ext}"

    if reencode:
        command = [
            "ffmpeg",
            "-i",
            local_input,
            "-c:v",
            "libx264",
            "-profile:v",
            "baseline",
            "-level",
            "3.0",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-b:a",
            "128k",
            "-movflags",
            "faststart",
            local_output,
        ]
    else:
        command = [
            "ffmpeg",
            "-i",
            local_input,
            "-c",
            "copy",
            "-movflags",
            "faststart",
            local_output,
        ]

    try:
        subprocess.run(command, check=True)
        shutil.copy2(local_output, input_file)
        print(f"Optimized video saved as {input_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error during optimization: {e}")
finally:
    shutil.rmtree(tmp_dir)


def install():
    """

    Installs the YAML Script runtime binary of the specified version.

    """
    import subprocess

    version = packaging.get_version("yamlscript")
    logger.warning(f"Installing YAML Script runtime binary version {version}...")
    result = subprocess.run(
        f"curl https://yamlscript.org/install | VERSION={version} LIB=1 bash",
        shell=True,
        check=True,
    )
    return result
