NOVA PORTABLE - DATA ENCRYPTION (AT REST)
=========================================

All case data, devices, consent records, locations, and audit logs live in
one SQLite file inside the data directory. To keep that file encrypted when
the stick is not in use, store it inside an encrypted container:

RECOMMENDED: VeraCrypt (free, cross-platform) https://www.veracrypt.fr

1. Create a container file on this stick, e.g.  nova.vc  (5-20 GB is plenty)
   - Windows : VeraCrypt GUI > Create Volume > Encrypted File Container
   - Linux   : veracrypt --text --create /media/usb/nova.vc
   - macOS   : VeraCrypt GUI, same as Windows

2. Mount it into the folder  secure/data  on this stick:
   - Windows : VeraCrypt > Select File > nova.vc > Select Drive >
               "Mount Options" > check "Mount volume to a NTFS folder" >
               choose <stick>\secure\data
     (secure\data must exist; create it if needed)
   - Linux   : mkdir -p secure/data
               veracrypt --text nova.vc secure/data
   - macOS   : mount via GUI to any folder, then symlink:
               ln -s /Volumes/NovaSecure secure/data

3. Run start_nova as usual. The launcher automatically uses secure/data
   when present and warns loudly when falling back to unencrypted storage.

4. When finished: stop NOVA (stop_nova), then DISMOUNT the container so all
   data is sealed inside nova.vc. Unencrypted leftovers must not remain.

NOTES
- The passphrase protects your evidence at rest. If you lose it, the data
  is unrecoverable by design.
- For chain-of-custody workflows, hash evidence files with the audited
  command  forensics.hash.file  before and after transport.
- Full-disk (hardware) encryption of the whole stick is also fine; then the
  plain data/ directory is acceptable.
