package ru.iu3.fclient;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import ru.iu3.fclient.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity implements TransactionEvents {

    static {
        System.loadLibrary("fclient");
        System.loadLibrary("mbedcrypto");
    }

    private ActivityMainBinding binding;
    private ActivityResultLauncher<Intent> activityResultLauncher;

    private String pin;

    private void testCrypto() {
        // 1. Инициализируем RNG
        int rc = initRng();
        Log.i("fclient_java", "initRng rc = " + rc);

        // 2. Генерим 16 случайных байт (просто чтобы проверить)
        byte[] rnd = randomBytes(16);
        if (rnd != null && rnd.length > 0) {
            Log.i("fclient_java", "rnd[0] = " + (rnd[0] & 0xFF));
        } else {
            Log.i("fclient_java", "rnd is null or empty");
        }

        // 3. Тестовый ключ 3DES (16 байт = 2-key 3DES)
        byte[] key = stringToHex("0123456789ABCDEF0123456789ABCDE0");

        // 4. Тестовые данные: 000000000000000102
        byte[] plain = stringToHex("000000000000000102");

        // 5. Шифруем
        byte[] enc = encrypt(key, plain);
        Log.i("fclient_java", "ENC length = " + (enc != null ? enc.length : -1));

        // 6. Расшифровываем
        byte[] dec = decrypt(key, enc);

        String plainHex = "";
        String decHex = "";
        String encHex = "";
        try {
            plainHex = new String(Hex.encodeHex(plain)).toUpperCase();
            decHex = new String(Hex.encodeHex(dec)).toUpperCase();
            encHex = new String(Hex.encodeHex(enc)).toUpperCase();
        } catch (Exception ex) {
            Log.e("fclient_java", "HEX encode failed", ex);
        }

        Log.i("fclient_java", "PLAIN = " + plainHex);
        Log.i("fclient_java", "ENC = " + encHex);
        Log.i("fclient_java", "DEC   = " + decHex);

        // выведу расшифрованный текст на экран тостом
        Toast.makeText(this, "DEC = " + decHex, Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        MainActivity.initRng();

        TextView tv = findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());

        testCrypto();


        activityResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                new ActivityResultCallback<ActivityResult>() {
                    @Override
                    public void onActivityResult(ActivityResult result) {
                        if (result.getResultCode() == Activity.RESULT_OK) {
                            Intent data = result.getData();
                            //String pin = data.getStringExtra("pin");
                            //Toast.makeText(MainActivity.this, pin, Toast.LENGTH_SHORT).show();
                            pin = data.getStringExtra("pin");
                            synchronized (MainActivity.this) {
                                MainActivity.this.notifyAll();
                            }
                        }
                    }
                }
        );
    }

    public native String stringFromJNI();

    public static native int initRng();
    public static native byte[] randomBytes(int num);

    public static native byte[] encrypt(byte[] key, byte[] data);
    public static native byte[] decrypt(byte[] key, byte[] data);

    public native boolean transaction(byte[] trd);

    public static byte[] stringToHex(String s) {
        byte[] hex;
        try {
            hex = Hex.decodeHex(s.toCharArray());
        } catch (DecoderException ex) {
            hex = null;
        }
        return hex;
    }

    @Override
    public String enterPin(int ptc, String amount) {
        pin = new String();
        Intent it = new Intent(MainActivity.this, PinpadActivity.class);
        it.putExtra("ptc", ptc);
        it.putExtra("amount", amount);
        synchronized (MainActivity.this) {
            activityResultLauncher.launch(it);
            try {
                MainActivity.this.wait();
            } catch (Exception ex) {
                //todo: log error
            }
        }
        return pin;
    }

    @Override
    public void transactionResult(boolean result) {
        runOnUiThread(() -> {
            Toast.makeText(MainActivity.this, result ? "ok" : "failed", Toast.LENGTH_SHORT).show();
        });
    }

    public void onButtonClick(View v) {
        byte[] trd = stringToHex("9F0206000000000100");
        transaction(trd);
    }
}