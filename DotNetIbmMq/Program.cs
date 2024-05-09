using System.Collections;
using System.Reflection;
using IBM.XMS;
using System.Security.Cryptography.X509Certificates;

namespace DotNetIbmMq;

internal class Program
{
    private static void Main()
    {
        IConnection? connection = default;
        ISession? session = default;
        IDestination? destination = default;
        IMessageProducer? messageProducer = default;

        try
        {
            var environmentVariablesDictionary = Environment.GetEnvironmentVariables();
            InstallCertificates(environmentVariablesDictionary);
            var factory = CreateConnectionFactory(environmentVariablesDictionary);

            connection = factory.CreateConnection();
            session = connection.CreateSession(false, AcknowledgeMode.AutoAcknowledge);
            destination = session.CreateQueue(environmentVariablesDictionary[Constants.MqQueueName]?.ToString());
            messageProducer = session.CreateProducer(destination);

            connection.Start();

            var message = session.CreateTextMessage();
            message.Text = "RealMadridCF-15";

            Console.WriteLine($"sending message: {message.Text}{Environment.NewLine}metadata: {message}");
            messageProducer.Send(message);
            Console.WriteLine("message sent");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Linked Exception Message: {GetLinkedExceptionMessage(ex)}{Environment.NewLine}Exception: {ex}");
        }
        finally
        {
            messageProducer?.Close();
            messageProducer?.Dispose();
            destination?.Dispose();
            session?.Dispose();
            connection?.Dispose();
        }
    }

    private static void InstallCertificates(IDictionary environmentVariablesDictionary)
    {
        if (IsTlsDisabled(environmentVariablesDictionary))
        {
            return;
        }

        var clientCertificatePath = environmentVariablesDictionary[Constants.MqClientCertificatePath]?.ToString();
        var clientCertificatePassword = environmentVariablesDictionary[Constants.MqClientCertificatePassword]?.ToString();
        if (string.IsNullOrWhiteSpace(clientCertificatePath) || string.IsNullOrWhiteSpace(clientCertificatePassword))
        {
            return;
        }

        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);

        var importCollection = new X509Certificate2Collection();
        importCollection.Import(clientCertificatePath, clientCertificatePassword, X509KeyStorageFlags.PersistKeySet);
        foreach (var cert in importCollection)
        {
            Console.WriteLine($"Processing Certificate: Subject: {cert.Subject}, Thumbprint: {cert.Thumbprint}");
            var alreadyExists = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count > 0;
            if (!alreadyExists)
            {
                store.Add(cert);
                Console.WriteLine($"Certificate installed successfully: Subject: {cert.Subject}");
            }
            else
            {
                Console.WriteLine($"Certificate already exists: Subject: {cert.Subject}");
            }
        }
    }

    private static IConnectionFactory CreateConnectionFactory(IDictionary environmentVariablesDictionary)
    {
        var factory = XMSFactoryFactory.GetInstance(XMSC.CT_WMQ).CreateConnectionFactory();
        factory.SetStringProperty(XMSC.WMQ_HOST_NAME, environmentVariablesDictionary[Constants.MqHost]?.ToString());
        factory.SetIntProperty(XMSC.WMQ_PORT, int.Parse(environmentVariablesDictionary[Constants.MqPort]!.ToString()!));
        factory.SetStringProperty(XMSC.WMQ_QUEUE_MANAGER, environmentVariablesDictionary[Constants.MqQueueManager]?.ToString());
        factory.SetStringProperty(XMSC.WMQ_CHANNEL, environmentVariablesDictionary[Constants.MqChannel]?.ToString());
        factory.SetIntProperty(XMSC.WMQ_CONNECTION_MODE, int.Parse(environmentVariablesDictionary[Constants.MqConnectionMode]!.ToString()!));
        return AddTlsConfiguration(factory, environmentVariablesDictionary);
    }

    private static IConnectionFactory AddTlsConfiguration(IConnectionFactory factory, IDictionary environmentVariablesDictionary)
    {
        if (IsTlsDisabled(environmentVariablesDictionary))
        { 
            return factory;
        }

        var repository = environmentVariablesDictionary[Constants.MqSslCertificateRepository]?.ToString();
        if (!string.IsNullOrWhiteSpace(repository))
        {
            factory.SetStringProperty(XMSC.WMQ_SSL_KEY_REPOSITORY, repository);
        }

        var cipherSpec = environmentVariablesDictionary[Constants.MqSslCipherSpec]?.ToString();
        if (!string.IsNullOrWhiteSpace(cipherSpec))
        {
            factory.SetStringProperty(XMSC.WMQ_SSL_CIPHER_SPEC, cipherSpec);
        }

        var peerName = environmentVariablesDictionary[Constants.MqSslPeerName]?.ToString();
        if (!string.IsNullOrWhiteSpace(peerName))
        {
            factory.SetStringProperty(XMSC.WMQ_SSL_PEER_NAME, peerName);
        }

        var label = environmentVariablesDictionary[Constants.MqClientCertificateLabel]?.ToString();
        if (!string.IsNullOrWhiteSpace(label))
        {
            factory.SetStringProperty(XMSC.WMQ_SSL_CLIENT_CERT_LABEL, label);
        }

        return factory;
    }

    public static string GetLinkedExceptionMessage(Exception ex)
    {
        var linkedExceptionProperty = ex.GetType().GetProperty("LinkedException", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance);
        var linkedEx = (Exception?)linkedExceptionProperty?.GetValue(ex);
        return linkedEx is null ? string.Empty : linkedEx.Message;
    }

    private static bool IsTlsDisabled(IDictionary environmentVariablesDictionary) =>
        "true".Equals(environmentVariablesDictionary[Constants.MqTlsDisabled]?.ToString(), StringComparison.OrdinalIgnoreCase);
}
