using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FileCryptApp.Models
{
    internal class FileMetaData
    {

        public string FileName { get; set; }

        public long SizeBytes { get; set; }

        public DateTime Created { get; set; }

        public string Algorithm { get; set; }

        public string HashAlgorithm { get; set; }

        public string HashValue { get; set; }   
        public string ToJson()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions
            {
                WriteIndented = false
            });
        }

        public static FileMetaData Create(string filepath, string algortihm,string hashAlgorithm)
        {
            var fileInfo = new System.IO.FileInfo(filepath);

            return new FileMetaData
            {
                FileName = System.IO.Path.GetFileName(filepath),
                SizeBytes = fileInfo.Length,
                Created = DateTime.Now,
                Algorithm = algortihm,
                HashAlgorithm = hashAlgorithm,


            };
        }
    }
}
