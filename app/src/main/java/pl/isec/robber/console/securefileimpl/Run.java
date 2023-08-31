package pl.isec.robber.console.securefileimpl;

import android.annotation.SuppressLint;
import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Looper;
import androidx.security.crypto.EncryptedFile;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Run {
    private final static String MASTER_KEY_ALIAS = "_androidx_security_master_key_";

    public static void main(String args[]){
        if(args.length != 2){
            System.err.println("Usage:\n\tpl.isec.robber.console.securefileimpl.Run <packageName> <encryptedFileName>");
            System.exit(1);
        }
        String packageName = args[0];
        String fileName = args[1];

        try {
            /** Initialize Android Keystore and application context **/
            initAndroidKeystore();
            Context context = initAppContext(packageName);

            /** Read EncryptedFile **/
            InputStream inputStream = new EncryptedFile.Builder(
                new File(context.getFilesDir(), fileName),
                context,
                MASTER_KEY_ALIAS,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build().openFileInput();

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int nextByte = inputStream.read();
            while (nextByte != -1) {
                byteArrayOutputStream.write(nextByte);
                nextByte = inputStream.read();
            }

            /** Print decrypted message **/
            System.out.println(
                byteArrayOutputStream.toString("UTF-8")
            );
        } catch(Exception e){
            e.printStackTrace();
        }
    }

    @SuppressLint({"BlockedPrivateApi"})
    private static void initAndroidKeystore() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        /** static AndroidKeyStoreProvider.install() **/
        Class cAndroidKeyStoreProvider = Class.forName("android.security.keystore2.AndroidKeyStoreProvider");
        Method install = cAndroidKeyStoreProvider.getDeclaredMethod("install");
        install.invoke(cAndroidKeyStoreProvider);
    }

    private static Context initAppContext(String packageName) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {
        /** Required for ActivityThread **/
        Looper.prepareMainLooper();

        /** static ActivityThread.systemMain() **/
        Class cActivityThread = Class.forName("android.app.ActivityThread");
        Method systemMain = cActivityThread.getDeclaredMethod("systemMain");
        Object activityThread = systemMain.invoke(cActivityThread);

        /** virtual activityThread.getPackageInfo(...) **/
        Class cCompatibilityInfo = Class.forName("android.content.res.CompatibilityInfo");
        Constructor compatibilityInfoConstructor = cCompatibilityInfo.getConstructor(ApplicationInfo.class, int.class, int.class, boolean.class);
        Object compatibilityInfo = compatibilityInfoConstructor.newInstance(new ApplicationInfo(), 0x02, 200, true);

        Method getPackageInfo = cActivityThread.getDeclaredMethod("getPackageInfo", String.class, cCompatibilityInfo, int.class);
        Object loadedApk = getPackageInfo.invoke(activityThread, packageName, compatibilityInfo, 0);

        /** virtual loadedApk.makeApplication(...) **/
        Class cLoadedApk = Class.forName("android.app.LoadedApk");
        Method makeApplication = cLoadedApk.getDeclaredMethod("makeApplication", boolean.class, Instrumentation.class);
        Application application = (Application) makeApplication.invoke(loadedApk,true, null);

        return application.getApplicationContext();
    }
}
