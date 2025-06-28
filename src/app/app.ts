import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CryptoService } from './services/crypto.service';

@Component({
  selector: 'app-root',
  imports: [ FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App {
  protected title = 'encrypt-text';
  masterKey = '';
  text = '';
  iv:string='';
  salt:string ='';
  encryptedText = '';
  decryptedText = '';

  private cryptoService = inject(CryptoService);

  async cryptText(){
    this.encryptedText = await this.cryptoService.encryptAES(this.text,this.masterKey,this.iv,this.salt);
  }

  async decryptText(){
    this.decryptedText = await this.cryptoService.decryptAES(this.encryptedText,this.masterKey,this.iv,this.salt);
  }

  randomIV(){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    this.iv = btoa(String.fromCharCode(...iv));
  }

  randomSALT(){
    const salt = crypto.getRandomValues(new Uint8Array(16));
    this.salt = btoa(String.fromCharCode(...salt));
  }
}
