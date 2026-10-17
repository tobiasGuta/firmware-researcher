package extract

import (
 "archive/tar"
 "context"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path"
 "path/filepath"
 "strings"
)

const (
 maxExportEntries = 50000
 maxExportBytes int64 = 512 << 20
 maxTarStreamBytes int64 = maxExportBytes + 64<<20
 maxExportFileBytes int64 = 512 << 20
)

type exportBuffer struct { data []byte }
func (b *exportBuffer) Write(p []byte)(int,error){n:=len(p);if len(b.data)<8192 {remain:=8192-len(b.data);if len(p)>remain {p=p[:remain]};b.data=append(b.data,p...)};return n,nil}
func (b *exportBuffer) String() string{return string(b.data)}

// Docker cp cannot read tmpfs mounts. docker exec tar can stream their bytes.
// The archive is parsed on the host with strict path, type and size limits.
func (Docker) Export(ctx context.Context, container, dest string) error {
 cmd:=exec.CommandContext(ctx,"docker","exec",container,"tar","-C","/scratch","-cf","-","binwalk.json","extracted")
 stdout,err:=cmd.StdoutPipe();if err!=nil{return err}
 stderr:=&exportBuffer{};cmd.Stderr=stderr
 if err:=cmd.Start();err!=nil{return fmt.Errorf("start tmpfs export: %w",err)}
 unpackErr:=unpackEvidenceArchive(ctx,io.LimitReader(stdout,maxTarStreamBytes+1),dest)
 if unpackErr!=nil {_=cmd.Process.Kill()}
 waitErr:=cmd.Wait()
 if unpackErr!=nil{return fmt.Errorf("invalid tmpfs export: %w",unpackErr)}
 if waitErr!=nil{return fmt.Errorf("tmpfs tar export failed: %v: %s",waitErr,stderr.String())}
 return nil
}

func unpackEvidenceArchive(ctx context.Context, stream io.Reader, dest string) error {
 tr:=tar.NewReader(stream)
 seen:=map[string]struct{}{}
 var bytes int64
 for entries:=0;;entries++ {
  if err:=ctx.Err();err!=nil{return err}
  if entries>=maxExportEntries{return errors.New("archive entry limit exceeded")}
  header,err:=tr.Next();if errors.Is(err,io.EOF){break};if err!=nil{return fmt.Errorf("tar header: %w",err)}
  name:=strings.TrimSuffix(header.Name,"/")
  if name=="" || name!=path.Clean(name) || path.IsAbs(name) || strings.Contains(name,"\\") || strings.HasPrefix(name,"../") || name==".." || !(name=="binwalk.json" || name=="extracted" || strings.HasPrefix(name,"extracted/")) {
   return fmt.Errorf("unsafe or unexpected archive path: %q",header.Name)
  }
  if _,ok:=seen[name];ok{return fmt.Errorf("duplicate archive entry: %s",name)}
  seen[name]=struct{}{}
  if name=="binwalk.json" && header.Typeflag!=tar.TypeReg && header.Typeflag!=tar.TypeRegA{return errors.New("signature log must be a regular file")}
  if name=="extracted" && header.Typeflag!=tar.TypeDir{return errors.New("extraction root must be a directory")}
  target:=filepath.Join(dest,filepath.FromSlash(name))
  if err:=safeDirectories(dest,filepath.Dir(target));err!=nil{return err}
  switch header.Typeflag {
  case tar.TypeDir:
   if err:=safeDirectories(dest,target);err!=nil{return err}
  case tar.TypeReg,tar.TypeRegA:
   if header.Size<0 || header.Size>maxExportFileBytes || header.Size>maxExportBytes-bytes{return errors.New("archive byte limit exceeded")}
   bytes+=header.Size
   f,err:=os.OpenFile(target,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if err!=nil{return err}
   _,copyErr:=io.CopyN(f,tr,header.Size);closeErr:=f.Close()
   if copyErr!=nil{return fmt.Errorf("archive content %s: %w",name,copyErr)}
   if closeErr!=nil{return closeErr}
  case tar.TypeSymlink:
   if len(header.Linkname)>4096 || name=="binwalk.json"{return errors.New("unsafe archive symlink")}
   if err:=os.Symlink(header.Linkname,target);err!=nil{return err}
  default:
   return fmt.Errorf("unsupported archive entry type %d at %s",header.Typeflag,name)
  }
 }
 if _,ok:=seen["binwalk.json"];!ok{return errors.New("signature log missing from archive")}
 info,err:=os.Lstat(filepath.Join(dest,"extracted"));if err!=nil || !info.IsDir() || info.Mode()&os.ModeSymlink!=0{return errors.New("extraction directory missing from archive")}
 return nil
}

// Directory creation must not follow symlink paths supplied by firmware.
func safeDirectories(root,dir string) error {
 rel,err:=filepath.Rel(root,dir);if err!=nil{return err}
 if rel=="." {return nil}
 if rel==".." || filepath.IsAbs(rel) || strings.HasPrefix(rel,".."+string(filepath.Separator)){return errors.New("archive path outside destination")}
 cur:=root
 for _,part:=range strings.Split(rel,string(filepath.Separator)){
  if part=="" || part=="."{continue}
  cur=filepath.Join(cur,part)
  st,err:=os.Lstat(cur)
  if errors.Is(err,os.ErrNotExist){if err=os.Mkdir(cur,0700);err!=nil{return err};continue}
  if err!=nil{return err}
  if !st.IsDir() || st.Mode()&os.ModeSymlink!=0{return fmt.Errorf("unsafe archive ancestor: %s",cur)}
 }
 return nil
}
