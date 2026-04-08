## For players:

Please visit the Sitting Ducks speedrunning discord server (https://discord.com/invite/kGgjPWd3Pq) for instructions on how to patch your game. You do not need to directly use this tool because pre-patched game executables are available here.

## Features

# Instant loading patch

When the game is running at 60fps, the game usually takes 10 seconds per loading zone. This tool makes it load instantly by untying the loading from the framerate. 

# Variable framerate removal

Removes the game's variable framerate system and locks fdelta at 1/60th of a second to make the game run correctly at 60fps. The game's variable framerate system caused a number of bugs (the game would run faster when playing at over 1000 FPS due to the developers setting the minimum fdelta to 0.001, the game would run at a different speed every time it's launched anywhere from 98%-107% of its intended speed due to the game calculating fdelta incorrectly and driving over the same ramp could cause the player to be launched at inconsistent heights). These bugs are fixed by removing the variable framerate.

# New game plus mod

Allows the player to start the game with all items unlocked if they wish

## Installation:

You must be running Linux for these instructions to work.

From root of project:

`make install`

## Uninstallation:

`pipx uninstall duckpatch`

## Usage:

See `duckpatch -h`
