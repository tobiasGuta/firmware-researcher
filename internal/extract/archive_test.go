package extract
import("archive/tar";"bytes";"context";"os";"path/filepath";"testing")

type archiveFixture struct{name string;kind byte;body string;link string}
func fixtureTar(t *testing.T, items ...archiveFixture)[]byte{
 t.Helper();b:=new(bytes.Buffer);w:=tar.NewWriter(b)
 for _,x:=range items {h:=&tar.Header{Name:x.name,Typeflag:x.kind,Mode:0600,Linkname:x.link};if x.kind==tar.TypeReg{h.Size=int64(len(x.body))};if err:=w.WriteHeader(h);err!=nil{t.Fatal(err)};if x.kind==tar.TypeReg{if _,err:=w.Write([]byte(x.body));err!=nil{t.Fatal(err)}}}
 if err:=w.Close();err!=nil{t.Fatal(err)};return b.Bytes()
}
func TestArchiveSafeExport(t *testing.T){
 root:=t.TempDir()
 data:=fixtureTar(t,archiveFixture{"binwalk.json",tar.TypeReg,"[]",""},archiveFixture{"extracted/",tar.TypeDir,"",""},archiveFixture{"extracted/root/",tar.TypeDir,"",""},archiveFixture{"extracted/root/binary",tar.TypeReg,"ELF",""},archiveFixture{"extracted/root/link",tar.TypeSymlink,"","/etc/passwd"})
 if err:=unpackEvidenceArchive(context.Background(),bytes.NewReader(data),root);err!=nil{t.Fatal(err)}
 if raw,err:=os.ReadFile(filepath.Join(root,"extracted/root/binary"));err!=nil || string(raw)!="ELF"{t.Fatalf("bad extracted file: %v",err)}
 if target,err:=os.Readlink(filepath.Join(root,"extracted/root/link"));err!=nil || target!="/etc/passwd"{t.Fatalf("bad link: %q %v",target,err)}
}
func TestArchiveRejectUnsafeEntries(t *testing.T){
 cases:=[][]archiveFixture{
  {{"../../escape",tar.TypeReg,"x",""}},
  {{"binwalk.json",tar.TypeReg,"[]",""},{"extracted",tar.TypeSymlink,"","/etc"}},
  {{"binwalk.json",tar.TypeReg,"[]",""},{"extracted/",tar.TypeDir,"",""},{"extracted/link",tar.TypeSymlink,"","/tmp"},{"extracted/link/evil",tar.TypeReg,"x",""}},
  {{"binwalk.json",tar.TypeReg,"[]",""},{"extracted/",tar.TypeDir,"",""},{"extracted/hard",tar.TypeLink,"","elsewhere"}},
  {{"binwalk.json",tar.TypeReg,"[]",""},{"binwalk.json",tar.TypeReg,"[]",""},{"extracted/",tar.TypeDir,"",""}},
  {{"extracted/",tar.TypeDir,"",""}},
 }
 for i,items:=range cases {t.Run(string(rune('a'+i)),func(t *testing.T){if err:=unpackEvidenceArchive(context.Background(),bytes.NewReader(fixtureTar(t,items...)),t.TempDir());err==nil{t.Fatal("accepted unsafe tar")}})}
}
