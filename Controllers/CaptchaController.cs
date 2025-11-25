using Microsoft.AspNetCore.Mvc;
using OpenQA.Selenium.BiDi.Modules.BrowsingContext;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

namespace aspapp.Controllers
{
    public class CaptchaController : Controller
    {
        [HttpGet]
        public IActionResult Generate()
        {
            string code = new Random().Next(1000, 9999).ToString();
            HttpContext.Session.SetString("CaptchaCode", code);

            using var bmp = new Bitmap(200, 40);
            using var background = Graphics.FromImage(bmp);
            background.Clear(Color.White);
            using var font = new Font("Arial", 20, FontStyle.Bold);
            background.DrawString(code, font, Brushes.Black, 10, 5);

            using var ms = new MemoryStream();

            string folder = @"../CybersecurityLessons/images";
            if (Directory.Exists(folder))
            {
                Console.WriteLine("That path exists already.");
            }
            else
            {
                Directory.CreateDirectory(folder);
            }
                
            string filePath = Path.Combine(folder, "captcha.png");

            bmp.Save(filePath, System.Drawing.Imaging.ImageFormat.Png);
            bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);

            return File(ms.ToArray(), "image/png");
        }
    }
}
