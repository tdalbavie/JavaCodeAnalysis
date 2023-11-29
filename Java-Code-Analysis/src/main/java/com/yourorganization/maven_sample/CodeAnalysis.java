// Originally started by Izabella Palange Github: Fortuneye, further built on by Thomas Dalbavie Github: tdalbavie.
package com.yourorganization.maven_sample;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.ReferenceType;
import com.github.javaparser.resolution.TypeSolver;
import com.github.javaparser.resolution.UnsolvedSymbolException;
import com.github.javaparser.resolution.types.ResolvedType;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Some code that uses JavaParser.
 */
public class CodeAnalysis {

    static HashSet<String> jreTypeList = new HashSet<>();

    // Initialize counters for different exception types
    static AtomicInteger customExceptionsThrown = new AtomicInteger();
    static AtomicInteger jreExceptionsThrown = new AtomicInteger();
    static AtomicInteger genericExceptionsThrown = new AtomicInteger();

    static int numPublicPermissionField = 0;
    static int numProtectedPermissionField = 0;
    static int numPrivatePermissionField = 0;
    static int numDefaultPermissionField = 0;

    static int numPublicPermissionMethod = 0;
    static int numProtectedPermissionMethod = 0;
    static int numPrivatePermissionMethod = 0;
    static int numDefaultPermissionMethod = 0;
    
    static List<String> jreExceptionList = Arrays.asList(
            "AbstractMethodError",
            "AssertionError",
            "BootstrapMethodError",
            "ClassCastException",
            "ClassCircularityError",
            "ClassFormatError",
            "ClassNotFoundException",
            "CloneNotSupportedException",
            "EnumConstantNotPresentException",
            "ExceptionInInitializerError",
            "IllegalAccessError",
            "IllegalAccessException",
            "IllegalArgumentException",
            "IllegalMonitorStateException",
            "IllegalStateException",
            "IllegalThreadStateException",
            "IncompatibleClassChangeError",
            "IndexOutOfBoundsException",
            "InstantiationError",
            "InstantiationException",
            "InternalError",
            "InterruptedException",
            "LinkageError",
            "NegativeArraySizeException",
            "NoClassDefFoundError",
            "NoSuchFieldError",
            "NoSuchFieldException",
            "NoSuchMethodError",
            "NoSuchMethodException",
            "NullPointerException",
            "NumberFormatException",
            "OutOfMemoryError",
            "SecurityException",
            "StackOverflowError",
            "StringIndexOutOfBoundsException",
            "TypeNotPresentException",
            "UnsatisfiedLinkError",
            "UnsupportedClassVersionError",
            "UnsupportedOperationException",
            "VerifyError",
            "VirtualMachineError",
            "AnnotationFormatError",
            "AnnotationTypeMismatchException",
            "IncompleteAnnotationException",
            "IllegalClassFormatException",
            "UnmodifiableClassException",
            "LambdaConversionException",
            "WrongMethodTypeException",
            "ManagementException",
            "MemoryTypeNotSupportedException",
            "RuntimeErrorException",
            "RuntimeMBeanException",
            "RuntimeOperationsException",
            "FindException",
            "ResolutionException",
            "ResolvedModule",
            "GenericSignatureFormatError",
            "InaccessibleObjectException",
            "InvocationTargetException",
            "MalformedParameterizedTypeException",
            "MalformedParametersException",
            "UndeclaredThrowableException",
            "BindException",
            "ConnectException",
            "HttpRetryException",
            "HttpURLConnection",
            "MalformedURLException",
            "NoRouteToHostException",
            "PortUnreachableException",
            "ProtocolException",
            "Proxy",
            "ProxySelector",
            "ServerSocket",
            "Socket",
            "SocketException",
            "SocketTimeoutException",
            "URI",
            "URL",
            "URLConnection",
            "URLDecoder",
            "URLEncoder",
            "UnknownHostException",
            "UnknownServiceException",
            "BufferOverflowException",
            "BufferUnderflowException",
            "ByteBuffer",
            "CharBuffer",
            "DoubleBuffer",
            "FloatBuffer",
            "IntBuffer",
            "InvalidMarkException",
            "LongBuffer",
            "MappedByteBuffer",
            "ReadOnlyBufferException",
            "ShortBuffer",
            "CharacterCodingException",
            "IllegalCharsetNameException",
            "MalformedInputException",
            "StandardCharsets",
            "UnsupportedCharsetException",
            "AccessDeniedException",
            "AtomicMoveNotSupportedException",
            "ClosedDirectoryStreamException",
            "ClosedFileSystemException",
            "ClosedWatchServiceException",
            "DirectoryIteratorException",
            "DirectoryNotEmptyException",
            "FileAlreadyExistsException",
            "FileSystemException",
            "FileVisitResult",
            "Files",
            "InvalidPathException",
            "LinkOption",
            "NoSuchFileException",
            "NotDirectoryException",
            "NotLinkException",
            "OpenOption",
            "AnnotationFormatError",
            "AnnotationTypeMismatchException",
            "AWTError",
            "AWTException",
            "BackingStoreException",
            "BadAttributeValueExpException",
            "BadBinaryOpValueExpException",
            "BadLocationException",
            "BadStringOperationException",
            "BrokenBarrierException",
            "CertificateException",
            "CertificateEncodingException",
            "CertificateExpiredException",
            "CertificateNotYetValidException",
            "CharacterCodingException",
            "ClassNotFoundException",
            "CloneNotSupportedException",
            "ConcurrentModificationException",
            "DataFormatException",
            "DatatypeConfigurationException",
            "DateTimeException",
            "DestroyFailedException",
            "ExecutionException",
            "ExpandVetoException",
            "FontFormatException",
            "GeneralSecurityException",
            "GSSException",
            "IllegalClassFormatException",
            "IllegalAccessException",
            "IllegalArgumentException",
            "IllegalMonitorStateException",
            "IllegalPathStateException",
            "IllegalSelectorException",
            "IllegalStateException",
            "ImagingOpException",
            "IncompleteAnnotationException",
            "IndexOutOfBoundsException",
            "InheritableThreadLocal",
            "InstantiationException",
            "InterruptedException",
            "InvalidApplicationException",
            "InvalidKeyException",
            "InvalidKeySpecException",
            "InvalidMarkException",
            "InvalidObjectException",
            "InvalidParameterException",
            "InvalidPathException",
            "InvalidPreferencesFormatException",
            "InvalidPropertiesFormatException",
            "InvalidTargetObjectTypeException",
            "InvocationTargetException",
            "JarException",
            "JAXBException",
            "JMRuntimeException",
            "JMXProviderException",
            "JMXServerErrorException",
            "JMException",
            "KeyAlreadyExistsException",
            "KeyException",
            "KeyManagementException",
            "KeyNotFoundException",
            "LineUnavailableException",
            "LSException",
            "MarshalException",
            "MediaException",
            "MimeTypeParseException",
            "MissingResourceException",
            "MBeanException",
            "MBeanRegistrationException",
            "MBeanServerException",
            "MonitorSettingException",
            "NoSuchAlgorithmException",
            "NoSuchAttributeException",
            "NoSuchFieldException",
            "NoSuchMethodException",
            "NotActiveException",
            "NotBoundException",
            "NotFoundException",
            "NotOwnerException",
            "NotSerializableException",
            "NotYetBoundException",
            "NotYetConnectedException",
            "NoClassDefFoundError",
            "NullPointerException",
            "NumberFormatException",
            "ObjectStreamException",
            "IOException",
            "OptionalDataException",
            "OverlappingFileLockException",
            "ParserConfigurationException",
            "PatternSyntaxException",
            "PrinterException",
            "PrivilegedActionException",
            "ProcessException",
            "PropertyVetoException",
            "ProtocolException",
            "ProviderException",
            "RemoteException",
            "RuntimeException",
            "SAXException",
            "SAXNotSupportedException",
            "SAXParseException",
            "ScriptException",
            "SecurityException",
            "ServerNotActiveException",
            "SOAPException",
            "SQLException",
            "SSLException",
            "SyncFailedException",
            "SyntaxErrorException",
            "TimeoutException",
            "TooManyListenersException",
            "TransformerException",
            "TransformerFactoryConfigurationError",
            "TransformerFactoryConfigurationError",
            "UnmodifiableClassException",
            "UnsupportedOperationException",
            "UnsupportedTemporalTypeException",
            "UnsupportedFlavorException",
            "UriSyntaxException",
            "UserException",
            "ValidationException",
            "VerifyError",
            "WSDLException",
            "WrongAdapter",
            "WrongPolicy",
            "XMLParseException",
            "XMLSignatureException",
            "XMLStreamException",
            "XPathException",
            "FileNotFoundException",
            "ZipException"
    );

    /*
    * Helper code for methodLineCount
    * */
    private static int countLines(String code) {
        int numLines = 0;
        //string split the given segment of code
        String[] lines = code.split("\r\n|\r|\n");
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                numLines++;
            }
        }
        return numLines;
    }

    private static boolean isJreException(ReferenceType exceptionType) {
        String packageName = exceptionType.getMetaModel().getPackageName();
        return packageName.startsWith("java.") || packageName.startsWith("javax.");
    }

    static int genericExceptionCaughtCount = 0;
    static int jreExceptionCaughtCount = 0;
    static int customExceptionCaughtCount = 0;


    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void exceptionCaughtCount(File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                CompilationUnit cu = StaticJavaParser.parse(file);
                List<MethodDeclaration> methods = cu.findAll(MethodDeclaration.class);

                for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                    List<CatchClause> catchClauses = method.findAll(CatchClause.class);
                    for (CatchClause catchClause : catchClauses) {
                    	if (catchClause.getParameter().getType().isClassOrInterfaceType()) {
	                        ClassOrInterfaceType exceptionType = catchClause.getParameter().getType().asClassOrInterfaceType();
	                        String exceptionName = exceptionType.getNameAsString();
	                        //System.out.println(exceptionName);
	                        
	                        if ("Exception".equals(exceptionName)) {
	                        	genericExceptionCaughtCount++;
	                        } else if (jreExceptionList.contains(exceptionName)) {
	                        	jreExceptionCaughtCount++;
	                        } else {
	                        	customExceptionCaughtCount++;
	                        }
                    	}
                    }
                }
        }).explore(pathDir);
    }

    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void exceptionThrownCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

            CompilationUnit cu = StaticJavaParser.parse(file);

            // for each method in the source file
            cu.findAll(MethodDeclaration.class).forEach(md -> {

                // count all exceptions declared in the method signature
                md.getThrownExceptions().forEach(te -> {
                    String exceptionName = te.toString();
                    if (exceptionName.startsWith("java.")) {
                        jreExceptionsThrown.getAndIncrement();
                    } else if (exceptionName.contains(".")) {
                        customExceptionsThrown.getAndIncrement();
                    }else if (jreExceptionList.contains(exceptionName)){
                        jreExceptionsThrown.getAndIncrement();
                    } else if (!exceptionName.equals("Exception") && !exceptionName.equals("Error")) {
                        customExceptionsThrown.getAndIncrement();
                    } else {
                        genericExceptionsThrown.getAndIncrement();
                    }
                });

                md.getBody().ifPresent(body -> body.findAll(ThrowStmt.class).forEach(stmt -> {
                    Expression expr = stmt.getExpression();
                    if (expr instanceof ObjectCreationExpr) {
                        ObjectCreationExpr objExpr = (ObjectCreationExpr) expr;
                        try {
                            ResolvedType exceptionType = objExpr.getType().resolve();
                            String fullyQualifiedName = exceptionType.asReferenceType().getQualifiedName();
                            
                            if (fullyQualifiedName.startsWith("java.")) {
                                jreExceptionsThrown.getAndIncrement();
                            } else if (fullyQualifiedName.contains(".")) {
                                customExceptionsThrown.getAndIncrement();
                            } else {
                                genericExceptionsThrown.getAndIncrement();
                            }
                        } catch (UnsolvedSymbolException e) {
                            // Additional checks before concluding it's a custom exception
                            String exceptionName = objExpr.getType().asString();
                            if (jreExceptionList.contains(exceptionName)) {
                                jreExceptionsThrown.getAndIncrement();
                            } else if (!exceptionName.equals("Exception") && !exceptionName.equals("Error")) {
                                customExceptionsThrown.getAndIncrement();
                            } else {
                                genericExceptionsThrown.getAndIncrement();
                            }
                        }
                    } else {
                        genericExceptionsThrown.getAndIncrement();
                    }
                }));

            });

                /*System.out.println("Custom exceptions thrown: " + customExceptionsThrown);
                System.out.println("JRE exceptions thrown: " + jreExceptionsThrown);
                System.out.println("Generic exceptions thrown: " + genericExceptionsThrown);*/

        }).explore(pathDir);
    }

    static int globalRecursiveCount = 0;
    static int globalNonRecursiveCount = 0;


    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void methodCallCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                CompilationUnit cu = StaticJavaParser.parse(file);
                // Visit each method in the CompilationUnit and count the number of method calls
                MethodCallVisitor visitor = new MethodCallVisitor();
                visitor.visit(cu, null);

                globalRecursiveCount += visitor.recursiveCount;
                globalNonRecursiveCount += visitor.nonRecursiveCount;

                // Print the results
                /*System.out.println("Non-recursive method calls: " + visitor.getNonRecursiveCount());
                System.out.println("Recursive method calls: " + visitor.getRecursiveCount());*/

        }).explore(pathDir);
    }

    static int inheritanceCounter = 0;
    static int interfaceCounter = 0;
    static int inheritanceAndInterfaceCounter = 0;
    static int classCounter = 0;
    // Creates a HashSet to be used in VariableVisitor for JRE checks.
    static HashSet<String> userDefinedTypeNames = new HashSet<String>();

    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void inheritanceCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);
        		// Clears the names it contains so the next project is not effected.
        		userDefinedTypeNames.clear();
                // Parse the source code file
                CompilationUnit cu = StaticJavaParser.parse(file);

                // Count the number of classes that use inheritance
                int countInheritance = 0;
                int countInterface = 0;
                int countBoth = 0;
                List<ClassOrInterfaceDeclaration> classesAndInterfaces = cu.findAll(ClassOrInterfaceDeclaration.class);
                for (ClassOrInterfaceDeclaration classOrInterface : classesAndInterfaces) {
                	//System.out.println(classOrInterface.getNameAsString());
                	userDefinedTypeNames.add(classOrInterface.getNameAsString());
                	
                    if (classOrInterface.getExtendedTypes().isNonEmpty()) {
                    	countInheritance++;
                    }
                    if (classOrInterface.isInterface()) {
                    	countInterface++;
                    }
                    if (countInterface != 0 && countInheritance != 0) {
                    	countBoth++;
                    }
                }
                classCounter += classesAndInterfaces.size();
                inheritanceCounter += countInheritance;
                interfaceCounter += countInterface;
                inheritanceAndInterfaceCounter += countBoth;

                // Print the result
                /*System.out.println("Number of classes that use inheritance: " + countInheritance);
                System.out.println("Number of classes that is an interface: " + countInterface);
                System.out.println("Number of classes that are both: " + countBoth);*/

        }).explore(pathDir);
    }

    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void memberPermissionCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);
            AtomicInteger numPublicField = new AtomicInteger();
            AtomicInteger numProtectedField = new AtomicInteger();
            AtomicInteger numPrivateField = new AtomicInteger();
            AtomicInteger numDefaultField = new AtomicInteger();

            AtomicInteger numPublicMethod = new AtomicInteger();
            AtomicInteger numProtectedMethod = new AtomicInteger();
            AtomicInteger numPrivateMethod = new AtomicInteger();
            AtomicInteger numDefaultMethod = new AtomicInteger();

                // Parse the source code file
                CompilationUnit cu = StaticJavaParser.parse(file);

                // Count the number of members with each permission

            //get number of permissions for FIELD DECLARATIONS
            //find every field declaration, depending on the modifier type, increment the counter for each one found
            cu.findAll(FieldDeclaration.class, fd -> fd.getModifiers().contains(Modifier.publicModifier()))
                    .forEach(fd -> numPublicField.getAndIncrement());
            cu.findAll(FieldDeclaration.class, fd -> fd.getModifiers().contains(Modifier.protectedModifier()))
                    .forEach(fd -> numProtectedField.getAndIncrement());
            cu.findAll(FieldDeclaration.class, fd -> fd.getModifiers().contains(Modifier.privateModifier()))
                    .forEach(fd -> numPrivateField.getAndIncrement());
            cu.findAll(FieldDeclaration.class, fd -> !fd.getModifiers().contains(Modifier.publicModifier())
                            && !fd.getModifiers().contains(Modifier.protectedModifier())
                            && !fd.getModifiers().contains(Modifier.privateModifier()))
                    .forEach(fd -> numDefaultField.getAndIncrement());

            //find every method declaration, depending on the modifier type, increment the counter for each one found
            cu.findAll(MethodDeclaration.class, md -> md.getModifiers().contains(Modifier.publicModifier())).forEach(md -> numPublicMethod.getAndIncrement());
            cu.findAll(MethodDeclaration.class, md -> md.getModifiers().contains(Modifier.protectedModifier())).forEach(md -> numProtectedMethod.getAndIncrement());
            cu.findAll(MethodDeclaration.class, md -> md.getModifiers().contains(Modifier.privateModifier())).forEach(md -> numPrivateMethod.getAndIncrement());
            cu.findAll(MethodDeclaration.class, md -> !md.getModifiers().contains(Modifier.publicModifier())
                            && !md.getModifiers().contains(Modifier.protectedModifier())
                            && !md.getModifiers().contains(Modifier.privateModifier()))
                    .forEach(md -> numDefaultMethod.getAndIncrement());

                numPublicPermissionField += numPublicField.get();
                numPrivatePermissionField += numPrivateField.get();
                numProtectedPermissionField += numProtectedField.get();
                numDefaultPermissionField += numDefaultField.get();

                numPublicPermissionMethod += numPublicMethod.get();
                numPrivatePermissionMethod += numPrivateMethod.get();
                numProtectedPermissionMethod += numProtectedMethod.get();
                numDefaultPermissionMethod += numDefaultMethod.get();

                // Print the results
                /*System.out.println("Number of public members: " + numPublicPermission);
                System.out.println("Number of protected members: " + numProtectedPermission);
                System.out.println("Number of private members: " + numPrivatePermission);
                System.out.println("Number of default members: " + numDefaultPermission);*/

        }).explore(pathDir);
    }

    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void memberCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                // Parse the source code file
                CompilationUnit cu = StaticJavaParser.parse(file);

                // Count the number of members in the class
                int numFields = cu.findAll(FieldDeclaration.class).size();
                int numMethods = cu.findAll(MethodDeclaration.class).size();

                numFieldsMember += numFields;
                numMethodsMember += numMethods;

                // Print the results
                /*System.out.println("Number of fields: " + numFieldsMember);
                System.out.println("Number of methods: " + numMethodsMember);
                System.out.println("Total number of members: " + (numFieldsMember + numMethodsMember));*/
    	
        }).explore(pathDir);
    }

    // Count the number of lines in each method
    static int numAccessorsLines = 0;
    static int numMutatorsLines = 0;
    static int numConstructorsLines = 0;
    static int numStaticMethodsLines = 0;
    static int numInstanceMethodsLines = 0;
    
    static int accessorsLinesZero = 0;
    static int accessorsLinesOne = 0;
    static int accessorsLinesTwo = 0;
    static int accessorsLinesThree = 0;
    static int accessorsLinesFour = 0;
    static int accessorsLinesFive = 0;
    static int accessorsLinesSix = 0;
    static int accessorsLinesSeven = 0;
    static int accessorsLinesEight = 0;
    static int accessorsLinesNine = 0;
    static int accessorsLinesTenOrMore = 0;
    
    static int mutatorsLinesZero = 0;
    static int mutatorsLinesOne = 0;
    static int mutatorsLinesTwo = 0;
    static int mutatorsLinesThree = 0;
    static int mutatorsLinesFour = 0;
    static int mutatorsLinesFive = 0;
    static int mutatorsLinesSix = 0;
    static int mutatorsLinesSeven = 0;
    static int mutatorsLinesEight = 0;
    static int mutatorsLinesNine = 0;
    static int mutatorsLinesTenOrMore = 0;
    
    static int constructorsLinesZero = 0;
    static int constructorsLinesOne = 0;
    static int constructorsLinesTwo = 0;
    static int constructorsLinesThree = 0;
    static int constructorsLinesFour = 0;
    static int constructorsLinesFive = 0;
    static int constructorsLinesSix = 0;
    static int constructorsLinesSeven = 0;
    static int constructorsLinesEight = 0;
    static int constructorsLinesNine = 0;
    static int constructorsLinesTenOrMore = 0;
    
    static int staticMethodsLinesZero = 0;
    static int staticMethodsLinesOne = 0;
    static int staticMethodsLinesTwo = 0;
    static int staticMethodsLinesThree = 0;
    static int staticMethodsLinesFour = 0;
    static int staticMethodsLinesFive = 0;
    static int staticMethodsLinesSix = 0;
    static int staticMethodsLinesSeven = 0;
    static int staticMethodsLinesEight = 0;
    static int staticMethodsLinesNine = 0;
    static int staticMethodsLinesTenOrMore = 0;
    
    static int instanceMethodsLinesZero = 0;
    static int instanceMethodsLinesOne = 0;
    static int instanceMethodsLinesTwo = 0;
    static int instanceMethodsLinesThree = 0;
    static int instanceMethodsLinesFour = 0;
    static int instanceMethodsLinesFive = 0;
    static int instanceMethodsLinesSix = 0;
    static int instanceMethodsLinesSeven = 0;
    static int instanceMethodsLinesEight = 0;
    static int instanceMethodsLinesNine = 0;
    static int instanceMethodsLinesTenOrMore = 0;

    static int numAccessors = 0;
    static int numMutators = 0;
    static int numConstructors = 0;
    static int numStaticMethods = 0;
    static int numInstanceMethods = 0;

    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void methodLineCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                CompilationUnit cu = StaticJavaParser.parse(file);
                
                boolean emptyMutator = false;
                
                for (MethodDeclaration md : cu.findAll(MethodDeclaration.class)) {

                    // Check if the method is an accessor or mutator method
                    String methodName = md.getNameAsString();

                    //if the name starts with get[Something], has no parameters, and isn't a void type, it's a getter/accessor
                    boolean isAccessor = (Pattern.matches("^get[A-Z].*", methodName) || Pattern.matches("^is[A-Z].*", methodName)) && md.getParameters().isEmpty() && !md.getType().isVoidType();

                    //if the name starts with set[Something], has one parameter, and is a void type, its a setter/mutator
                    boolean isMutator = Pattern.matches("^set[A-Z].*", methodName) && md.getParameters().size() == 1 && md.getType().isVoidType();

                    int method = countLines(md.getBody().toString()) - 2;

                    if (isAccessor) {
                        numAccessors++;
                        
                        if (method == 0)
                        	accessorsLinesZero++;
                        else if (method == 1)
                        	accessorsLinesOne++;
                        else if (method == 2)
                        	accessorsLinesTwo++;
                        else if (method == 3)
                        	accessorsLinesThree++;
                        else if (method == 4)
                        	accessorsLinesFour++;
                        else if (method == 5)
                        	accessorsLinesFive++;
                        else if (method == 6)
                        	accessorsLinesSix++;
                        else if (method == 7)
                        	accessorsLinesSeven++;
                        else if (method == 8)
                        	accessorsLinesEight++;
                        else if (method == 9)
                        	accessorsLinesNine++;
                        else if (method >= 10)
                        	accessorsLinesTenOrMore++;
                        
                        numAccessorsLines += method;
                    } else if (isMutator) {
                        numMutators++;
                        
                        if (method == 0)
                        {
                        	mutatorsLinesZero++;
                        	System.out.print(" " + methodName);
                        	emptyMutator = true;
                        }
                        else if (method == 1)
                        	mutatorsLinesOne++;
                        else if (method == 2)
                        	mutatorsLinesTwo++;
                        else if (method == 3)
                        	mutatorsLinesThree++;
                        else if (method == 4)
                        	mutatorsLinesFour++;
                        else if (method == 5)
                        	mutatorsLinesFive++;
                        else if (method == 6)
                        	mutatorsLinesSix++;
                        else if (method == 7)
                        	mutatorsLinesSeven++;
                        else if (method == 8)
                        	mutatorsLinesEight++;
                        else if (method == 9)
                        	mutatorsLinesNine++;
                        else if (method >= 10)
                        	mutatorsLinesTenOrMore++;
                        
                        numMutatorsLines += method;
                    } else if (md.isStatic()) {
                        numStaticMethods++;
                        
                        if (method == 0)
                        	staticMethodsLinesZero++;
                        else if (method == 1)
                        	staticMethodsLinesOne++;
                        else if (method == 2)
                        	staticMethodsLinesTwo++;
                        else if (method == 3)
                        	staticMethodsLinesThree++;
                        else if (method == 4)
                        	staticMethodsLinesFour++;
                        else if (method == 5)
                        	staticMethodsLinesFive++;
                        else if (method == 6)
                        	staticMethodsLinesSix++;
                        else if (method == 7)
                        	staticMethodsLinesSeven++;
                        else if (method == 8)
                        	staticMethodsLinesEight++;
                        else if (method == 9)
                        	staticMethodsLinesNine++;
                        else if (method >= 10)
                        	staticMethodsLinesTenOrMore++;
                        
                        numStaticMethodsLines += method;
                    } else {
                        numInstanceMethods++;
                        
                        if (method == 0)
                        	instanceMethodsLinesZero++;
                        else if (method == 1)
                        	instanceMethodsLinesOne++;
                        else if (method == 2)
                        	instanceMethodsLinesTwo++;
                        else if (method == 3)
                        	instanceMethodsLinesThree++;
                        else if (method == 4)
                        	instanceMethodsLinesFour++;
                        else if (method == 5)
                        	instanceMethodsLinesFive++;
                        else if (method == 6)
                        	instanceMethodsLinesSix++;
                        else if (method == 7)
                        	instanceMethodsLinesSeven++;
                        else if (method == 8)
                        	instanceMethodsLinesEight++;
                        else if (method == 9)
                        	instanceMethodsLinesNine++;
                        else if (method >= 10)
                        	instanceMethodsLinesTenOrMore++;
                        
                        numInstanceMethodsLines += method;
                    }
                }
                
                if (emptyMutator)
                {
                	System.out.println();
                }

                // Count the number of lines in each constructor
                for (ConstructorDeclaration constructor : cu.findAll(ConstructorDeclaration.class)) {
                    numConstructors++;
                    int method = countLines(constructor.getBody().toString()) - 2;
                    
                    if (method == 0)
                    	constructorsLinesZero++;
                    else if (method == 1)
                    	constructorsLinesOne++;
                    else if (method == 2)
                    	constructorsLinesTwo++;
                    else if (method == 3)
                    	constructorsLinesThree++;
                    else if (method == 4)
                    	constructorsLinesFour++;
                    else if (method == 5)
                    	constructorsLinesFive++;
                    else if (method == 6)
                    	constructorsLinesSix++;
                    else if (method == 7)
                    	constructorsLinesSeven++;
                    else if (method == 8)
                    	constructorsLinesEight++;
                    else if (method == 9)
                    	constructorsLinesNine++;
                    else if (method >= 10)
                    	constructorsLinesTenOrMore++;
                    
                    numConstructorsLines += method;
                }

                // Print the results
                /*System.out.println("Number of lines in accessors: " + numAccessors);
                System.out.println("Number of lines in mutators: " + numMutators);
                System.out.println("Number of lines in constructors: " + numConstructors);
                System.out.println("Number of lines in static methods: " + numStaticMethods);
                System.out.println("Number of lines in instance methods: " + numInstanceMethods);*/

        }).explore(pathDir);
    }

    static int methodParams = 0;
    static int paramsZero = 0;
    static int paramsOne = 0;
    static int paramsTwo = 0;
    static int paramsThree = 0;
    static int paramsFour = 0;
    static int paramsFive = 0;
    static int paramsSix = 0;
    static int paramsSevenorMore = 0;

    static int methodsZero = 0;
    static int methodsOne = 0;
    static int methodsTwo = 0;
    static int methodsThree = 0;
    static int methodsFour = 0;
    static int methodsFive = 0;
    static int methodsSix = 0;
    static int methodsSeven = 0;
    static int methodsEight = 0;
    static int methodsNine = 0;
    static int methodsTenOrMore = 0;
    static int methodsHundredOrMore = 0;
    static int numMethodsMember = 0;


    /*
     * Raw counts and distributions of number of parameters a method requires
     * */
    public static void methodCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                CompilationUnit cu = StaticJavaParser.parse(file);

                for (ClassOrInterfaceDeclaration classDecl : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                    if (!classDecl.isInterface()) {
                        methodParams += classDecl.getMethods().size();
                        int numMethds = classDecl.getMethods().size();

                        //System.out.println("Number of methods: " + classDecl.getMethods().size());
                        if (classDecl.getMethods().isEmpty()) {
                            methodsZero++;
                            numMethodsMember++;
                        } else if (numMethds == 1) {
                            methodsOne++;
                            numMethodsMember++;
                        } else if (numMethds == 2) {
                            methodsTwo++;
                            numMethodsMember++;
                        } else if (numMethds == 3) {
                            methodsThree++;
                            numMethodsMember++;
                        } else if (numMethds == 4) {
                            methodsFour++;
                            numMethodsMember++;
                        } else if (numMethds == 5) {
                            methodsFive++;
                            numMethodsMember++;
                        } else if (numMethds == 6) {
                            methodsSix++;
                            numMethodsMember++;
                        } else if (numMethds == 7) {
                            methodsSeven++;
                            numMethodsMember++;
                        } else if (numMethds == 8) {
                            methodsEight++;
                            numMethodsMember++;
                        } else if (numMethds == 9) {
                            methodsNine++;
                            numMethodsMember++;
                        } else if (numMethds >= 10) {
                            methodsTenOrMore++;
                            numMethodsMember++;
                        }
                        
                        if (numMethds >= 100) {
                            methodsHundredOrMore++;
                        }
                        
                        if (numMethds >= 1000)
                        	System.out.println("Methods: " + numMethds);
                        
                    }
                }
        }).explore(pathDir);
    }
    
    static int fieldsZero = 0;
    static int fieldsOne = 0;
    static int fieldsTwo = 0;
    static int fieldsThree = 0;
    static int fieldsFour = 0;
    static int fieldsFive = 0;
    static int fieldsSix = 0;
    static int fieldsSeven = 0;
    static int fieldsEight = 0;
    static int fieldsNine = 0;
    static int fieldsTenOrMore = 0;
    static int fieldsHundredOrMore = 0;
    static int numFieldsMember = 0;
    
    public static void fieldCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                CompilationUnit cu = StaticJavaParser.parse(file);

                for (ClassOrInterfaceDeclaration classDecl : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                    if (!classDecl.isInterface()) {
                        int numFields = classDecl.getFields().size();

                        //System.out.println("Number of methods: " + classDecl.getMethods().size());
                        if (classDecl.getFields().isEmpty()) {
                        	fieldsZero++;
                        	numFieldsMember++;
                        } else if (numFields == 1) {
                        	fieldsOne++;
                        	numFieldsMember++;
                        } else if (numFields == 2) {
                        	fieldsTwo++;
                        	numFieldsMember++;
                        } else if (numFields == 3) {
                        	fieldsThree++;
                        	numFieldsMember++;
                        } else if (numFields == 4) {
                        	fieldsFour++;
                        	numFieldsMember++;
                        } else if (numFields == 5) {
                        	fieldsFive++;
                        	numFieldsMember++;
                        } else if (numFields == 6) {
                        	fieldsSix++;
                        	numFieldsMember++;
                        } else if (numFields == 7) {
                        	fieldsSeven++;
                        	numFieldsMember++;
                        } else if (numFields == 8) {
                        	fieldsEight++;
                        	numFieldsMember++;
                        } else if (numFields == 9) {
                        	fieldsNine++;
                        	numFieldsMember++;
                        } else if (numFields >= 10) {
                        	fieldsTenOrMore++;
                        	numFieldsMember++;
                        }
                        
                        if (numFields >= 100) {
                        	fieldsHundredOrMore++;
                        }
                        
                        if (numFields >= 1000)
                        	System.out.println("Fields: " + numFields);

                    }
                }
        }).explore(pathDir);
    }

    static int globalParamCount = 0;

    /*
    * Raw counts and distributions of number of parameters a method requires
    * */
    public static void parameterCount (File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

            CompilationUnit cu = StaticJavaParser.parse(file);

            for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                    globalParamCount += method.getParameters().size();

                    if(method.getParameters().isEmpty()){
                        paramsZero++;
                    } else if(method.getParameters().size() == 1){
                        paramsOne++;
                    } else if(method.getParameters().size() == 2){
                        paramsTwo++;
                    } else if(method.getParameters().size() == 3){
                        paramsThree++;
                    } else if(method.getParameters().size() == 4){
                        paramsFour++;
                    } else if(method.getParameters().size() == 5){
                        paramsFive++;
                    } else if(method.getParameters().size() == 6){
                        paramsSix++;
                    } else if(method.getParameters().size() >= 7) {
                        paramsSevenorMore++;
                    }
                }

        }).explore(pathDir);
    }
    
    static int globalPrimitiveTypeCount = 0;
    static int globalCompositeTypeCount = 0;
    static int globalEnumerationCount = 0;
    static int globalJRECount = 0;
    static int globalHomemadeCount = 0;
    static int globalBooleanCount = 0;
    static int globalCharCount = 0;
    static int globalShortCount = 0;
    static int globalLongCount = 0;
    static int globalByteCount = 0;
    static int globalFloatCount = 0;
    static int globalDoubleCount = 0;
    static int globalIntCount = 0;
    // Stores final constants for use in integer literal count.
    static HashMap<String, Number> globalFinalIntegerLiterals = new HashMap<String, Number>();
    
    /*
     * Frequency of data types used in parameters, local variables, and members of classes:
     * Raw counts and percentage of primitive vs composite types
     * Raw counts and percentage of each of the primitive types
     * */
    public static void variableTypeCount(File pathDir) throws Exception {

        /*
         * list of primitive types in java:
         * boolean
         * byte
         * short
         * char
         * int
         * long
         * float
         * double
         * */

        /*
         * we want raw number counts of composite types
         * (types containing primitive types, ie objects)
         * */

        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                TypeSolver typeSolver = new CombinedTypeSolver();

                JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
                StaticJavaParser
                        .getConfiguration()
                        .setSymbolResolver(symbolSolver);

                CompilationUnit cu = StaticJavaParser.parse(file);

                VariableVisitor visitor = new VariableVisitor();
                cu.accept(visitor, null);

                globalPrimitiveTypeCount += visitor.primitiveTypeCount.get();
                globalCompositeTypeCount += visitor.compositeTypeCount.get();
                globalEnumerationCount += visitor.enumCount.get();
                globalJRECount += visitor.JRECount.get();
                globalHomemadeCount += visitor.homemadeCount.get();
                globalBooleanCount += visitor.booleanCount.get();
                globalCharCount += visitor.charCount.get();
                globalShortCount += visitor.shortCount.get();
                globalLongCount += visitor.longCount.get();
                globalByteCount += visitor.byteCount.get();
                globalFloatCount += visitor.floatCount.get();
                globalDoubleCount += visitor.doubleCount.get();
                globalIntCount += visitor.intCount.get();
                for(Map.Entry<String, Number> entry : visitor.finalIntegerLiterals.entrySet())
                {
                	globalFinalIntegerLiterals.put(entry.getKey(), entry.getValue());
                }

                /*System.out.println("Number of primitive types: " + visitor.primitiveTypeCount);
                System.out.println("Number of composite types: " + visitor.compsositeTypeCount);
                System.out.println("Number of boolean: " + visitor.booleanCount);
                System.out.println("Number of char: " + visitor.charCount);
                System.out.println("Number of short: " + visitor.shortCount);
                System.out.println("Number of long: " + visitor.longCount);
                System.out.println("Number of byte: " + visitor.byteCount);
                System.out.println("Number of float: " + visitor.floatCount);
                System.out.println("Number of double: " + visitor.doubleCount);
                System.out.println("Number of int: " + visitor.intCount);*/
        }).explore(pathDir);
    }
    
    static int globalIfCount = 0;
    static int globalWhileCount = 0;
    static int globalForCount = 0;
    static int globalEnhancedForCount = 0;
    static int globalSwitchCaseCount = 0;
    
    public static void variableStatementCount(File pathDir) throws Exception {

        /*
         * List of statements to be counted:
         * If
         * while
         * For
         * Enhanced for
         * Switch
         * */

        /*
         * we want raw number counts of composite types
         * (types containing primitive types, ie objects)
         * */

        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                CompilationUnit cu = StaticJavaParser.parse(file);

                StatementVisitor visitor = new StatementVisitor();
                cu.accept(visitor, null);

                globalIfCount += visitor.ifCount.get();
                globalWhileCount += visitor.whileCount.get();
                globalForCount += visitor.forCount.get();
                globalEnhancedForCount += visitor.enhancedForCount.get();
                globalSwitchCaseCount += visitor.caseCount.get();

                /*System.out.println("Number of if statements: " + visitor.ifCount);
                System.out.println("Number of while statements: " + visitor.whileCount);
                System.out.println("Number of for statements: " + visitor.forCount);
                System.out.println("Number of for each statements: " + visitor.enhancedForCount);
                System.out.println("Number of switch cases: " + visitor.caseCount);*/
                
        }).explore(pathDir);
    }
    
    static int globalConstantCount = 0;
    static int globalConstantCountInRange = 0;
    static int globalConstantCountInDeclaration = 0;
    
    public static void constantCount(File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);

                CompilationUnit cu = StaticJavaParser.parse(file);

                IntegerLiteralVisitor visitor = new IntegerLiteralVisitor();
                cu.accept(visitor, null);

                globalConstantCount += visitor.countConstants.get();
                globalConstantCountInRange += visitor.countConstantsInRange.get();
                globalConstantCountInDeclaration += visitor.countConstantsInDeclarations.get();

                /*System.out.println("Number of constants: " + visitor.countConstants);
                System.out.println("Number of constants in range of +/-32: " + visitor.countConstantsInRange);*/
                
        }).explore(pathDir);
    }

    public static String fileToString(File file) throws IOException, FileNotFoundException {
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        StringBuilder stringBuilder = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            stringBuilder.append(line);
            stringBuilder.append(System.lineSeparator());
        }
        reader.close();
        return stringBuilder.toString();
    }

    static int globallineCount = 0;

    static void javaLineCount(File pathDir) throws Exception {
        new DirExplorer((level, path, file) -> path.endsWith(".java"), (level, path, file) -> {
            //System.out.println("\n" + path);
            // Specify the Java source code file to count lines

            /*String fullFile = fileToString(file);
            int lineCount = countLines(fullFile);
            globallineCount += lineCount;*/

            int numLines = 0;
            int lineCount = 0;

            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                while (reader.readLine() != null) {
                    lineCount++;
                    globallineCount++;
                }
            }

            // Parse the Java source code file using JavaParser
            /*CompilationUnit cu = StaticJavaParser.parse(file);

            // Get all the types (classes and interfaces) declared in the source code file
            cu.getTypes().forEach(type -> {
                // Get the name of the type
                String typeName = type.getName().asString();

                // Get the number of lines of the type
                int lineCount = type.getEnd().get().line - type.getBegin().get().line + 1;

                globallineCount += lineCount;
            });*/
            // Print the result
            //System.out.println(lineCount + " lines");
        }).explore(pathDir);
        }


    public static void main(String[] args) throws Exception {
    	
    	// Initializes the full list of JRE data type names.
        String filename = "C:\\Users\\tdalbavie\\git\\JavaCodeAnalysis\\Java-Code-Analysis\\jreTypeList.txt";

        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                jreTypeList.add(line.trim());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        int typesize = jreTypeList.size();
        
        int caughtErrors = 0;
        //File newDir = new File("C:\\Users\\choco\\OneDrive - University at Albany - SUNY\\CLASSES\\SOPHOMORE\\SPRING 2021\\ICSI213 - Data St\\PROJECTS\\Project 4\\PROJ4");
        //5379
        //JavaParser cannot handle 4217 and 5070 so it is skipped, this project causes infinite recursion in JavaParser itself.
        for(int i = 0; i < 5379; i++) {
        	if (i != 4217 && i != 5070) {
	            String directory = "C:\\Users\\tdalbavie\\Documents\\Source Code\\REPOS\\" + i + "\\";
	            //"C:\\Users\\tdalbavie\\Documents\\Source Code\\REPOS\\" + i + "\\"
	            //"C:\\Users\\tdalbavie\\git\\JavaCodeAnalysisTestProgram\\"
	            //File newDir = new File("C:\\Users\\choco\\OneDrive - University at Albany - SUNY\\CLASSES\\SOPHOMORE\\SPRING 2021\\ICSI213 - Data St\\PROJECTS\\Project 2\\PROJECT 2");
	            File newDir = new File(directory);
	            try {
	            	inheritanceCount(newDir);
	            	variableTypeCount(newDir);
	                variableStatementCount(newDir);
	                constantCount(newDir);
	                methodCount(newDir);
	                fieldCount(newDir);
	                parameterCount(newDir);
	                methodLineCount(newDir);
	                memberPermissionCount(newDir);
	                methodCallCount(newDir);
	                exceptionThrownCount(newDir);
	                exceptionCaughtCount(newDir);
	                javaLineCount(newDir);
	                System.out.println(i);
	                globalFinalIntegerLiterals = new HashMap<String, Number>(); // Clears the HashMap after the program.
	            }catch(Exception e){
	            	//e.printStackTrace();
	                System.out.println("CAUGHT(" + i + ")");
	                caughtErrors++;
	                continue;
	            }
        	}
        	// Counts 4217 as an error.
        	else
        	{
        		System.out.println("CAUGHT(" + i + ")");
                caughtErrors++;
                continue;
        	}
        }

        /*variableTypeCount(newDir);
        methodCount(newDir);
        parameterCount(newDir);
        methodLineCount(newDir);
        memberCount(newDir);
        memberPermissionCount(newDir);
        inheritanceCount(newDir);
        methodCallCount(newDir);
        exceptionThrownCount(newDir);
        //exceptionCaughtCount(newDir);
        javaLineCount(newDir);*/

        System.out.println("CAUGHT ERRORS: " + caughtErrors);
        System.out.println("\nTOTALS\n");
        System.out.println("\nVARIABLE TOTALS: ");
        System.out.println("Number of primitive types: " + globalPrimitiveTypeCount);
        System.out.println("Number of composite types: " + globalCompositeTypeCount);
        System.out.println("Number of enumeration composite types: " + globalEnumerationCount);
        System.out.println("Number of JRE composite types: " + globalJRECount);
        System.out.println("Number of homemade composite types: " + globalHomemadeCount);
        System.out.println("Number of boolean: " + globalBooleanCount);
        System.out.println("Number of char: " + globalCharCount);
        System.out.println("Number of short: " + globalShortCount);
        System.out.println("Number of long: " + globalLongCount);
        System.out.println("Number of byte: " + globalByteCount);
        System.out.println("Number of float: " + globalFloatCount);
        System.out.println("Number of double: " + globalDoubleCount);
        System.out.println("Number of int: " + globalIntCount);
        
        System.out.println("\nSTATEMENT NUMBER TOTALS:");
        System.out.println("Number of if statements: " + globalIfCount);
        System.out.println("Number of while statements: " + globalWhileCount);
        System.out.println("Number of for statements: " + globalForCount);
        System.out.println("Number of enhanced for statements: " + globalEnhancedForCount);
        System.out.println("Number of case blocks: " + globalSwitchCaseCount);
        
        System.out.println("\nCONSTANT NUMBER TOTALS:");
        System.out.println("Number of constants: " + globalConstantCount);
        System.out.println("Number of constants in range of +/-32: " + globalConstantCountInRange);
        System.out.println("Number of constants out of range of +/-32: " + (globalConstantCount - globalConstantCountInRange));
        System.out.println("Number of constants used in declaration: " + globalConstantCountInDeclaration);
        System.out.println("Number of constants not used in declaration: " + (globalConstantCount - globalConstantCountInDeclaration));
        

        System.out.println("\nPARAMETER NUMBER TOTALS:");
        System.out.println("Number of methods with 0 parameters: " + paramsZero);
        System.out.println("Number of methods with 1 parameters: " + paramsOne);
        System.out.println("Number of methods with 2 parameters: " + paramsTwo);
        System.out.println("Number of methods with 3 parameters: " + paramsThree);
        System.out.println("Number of methods with 4 parameters: " + paramsFour);
        System.out.println("Number of methods with 5 parameters: " + paramsFive);
        System.out.println("Number of methods with 6 parameters: " + paramsSix);
        System.out.println("Number of methods with 7+ parameters: " + paramsSevenorMore);
        System.out.println("Number of total Parameters: " + globalParamCount);

        System.out.println("\nMETHOD NUMBER TOTALS:");
        System.out.println("Number of classes with 0 methods: " + methodsZero);
        System.out.println("Number of classes with 1 methods: " + methodsOne);
        System.out.println("Number of classes with 2 methods: " + methodsTwo);
        System.out.println("Number of classes with 3 methods: " + methodsThree);
        System.out.println("Number of classes with 4 methods: " + methodsFour);
        System.out.println("Number of classes with 5 methods: " + methodsFive);
        System.out.println("Number of classes with 6 methods: " + methodsSix);
        System.out.println("Number of classes with 7 methods: " + methodsSeven);
        System.out.println("Number of classes with 8 methods: " + methodsEight);
        System.out.println("Number of classes with 9 methods: " + methodsNine);
        System.out.println("Number of classes with 10+ methods: " + methodsTenOrMore);
        System.out.println("Number of classes with 100+ methods: " + methodsHundredOrMore);
        System.out.println("Number of total Methods: " + methodParams);
        
        System.out.println("\nFIELD NUMBER TOTALS:");
        System.out.println("Number of classes with 0 fields: " + fieldsZero);
        System.out.println("Number of classes with 1 fields: " + fieldsOne);
        System.out.println("Number of classes with 2 fields: " + fieldsTwo);
        System.out.println("Number of classes with 3 fields: " + fieldsThree);
        System.out.println("Number of classes with 4 fields: " + fieldsFour);
        System.out.println("Number of classes with 5 fields: " + fieldsFive);
        System.out.println("Number of classes with 6 fields: " + fieldsSix);
        System.out.println("Number of classes with 7 fields: " + fieldsSeven);
        System.out.println("Number of classes with 8 fields: " + fieldsEight);
        System.out.println("Number of classes with 9 fields: " + fieldsNine);
        System.out.println("Number of classes with 10+ fields: " + fieldsTenOrMore);
        System.out.println("Number of classes with 100+ fields: " + fieldsHundredOrMore);

        System.out.println("\nNUMBER OF ACCESS/MUT/CONST/STATIC/INST METHODS:");
        System.out.println("Number of accessors: " + numAccessors);
        System.out.println("Number of mutators: " + numMutators);
        System.out.println("Number of constructors: " + numConstructors);
        System.out.println("Number of static methods: " + numStaticMethods);
        System.out.println("Number of instance methods: " + numInstanceMethods);
        System.out.println("Number of lines in accessors: " + numAccessorsLines);
        System.out.println("Number of lines in mutators: " + numMutatorsLines);
        System.out.println("Number of lines in constructors: " + numConstructorsLines);
        System.out.println("Number of lines in static methods: " + numStaticMethodsLines);
        System.out.println("Number of lines in instance methods: " + numInstanceMethodsLines);

        System.out.println("\nNUMBER OF LINES IN CONSTRUCTORS");
        System.out.println("Number of constructors with 0 lines: " + constructorsLinesZero);
        System.out.println("Number of constructors with 1 lines: " + constructorsLinesOne);
        System.out.println("Number of constructors with 2 lines: " + constructorsLinesTwo);
        System.out.println("Number of constructors with 3 lines: " + constructorsLinesThree);
        System.out.println("Number of constructors with 4 lines: " + constructorsLinesFour);
        System.out.println("Number of constructors with 5 lines: " + constructorsLinesFive);
        System.out.println("Number of constructors with 6 lines: " + constructorsLinesSix);
        System.out.println("Number of constructors with 7 lines: " + constructorsLinesSeven);
        System.out.println("Number of constructors with 8 lines: " + constructorsLinesEight);
        System.out.println("Number of constructors with 9 lines: " + constructorsLinesNine);
        System.out.println("Number of constructors with 10+ lines: " + constructorsLinesTenOrMore);
        
        System.out.println("\nNUMBER OF LINES IN ACCESSORS");
        System.out.println("Number of accessors with 0 lines: " + accessorsLinesZero);
        System.out.println("Number of accessors with 1 lines: " + accessorsLinesOne);
        System.out.println("Number of accessors with 2 lines: " + accessorsLinesTwo);
        System.out.println("Number of accessors with 3 lines: " + accessorsLinesThree);
        System.out.println("Number of accessors with 4 lines: " + accessorsLinesFour);
        System.out.println("Number of accessors with 5 lines: " + accessorsLinesFive);
        System.out.println("Number of accessors with 6 lines: " + accessorsLinesSix);
        System.out.println("Number of accessors with 7 lines: " + accessorsLinesSeven);
        System.out.println("Number of accessors with 8 lines: " + accessorsLinesEight);
        System.out.println("Number of accessors with 9 lines: " + accessorsLinesNine);
        System.out.println("Number of accessors with 10+ lines: " + accessorsLinesTenOrMore);
        
        System.out.println("\nNUMBER OF LINES IN MUTATORS");
        System.out.println("Number of mutators with 0 lines: " + mutatorsLinesZero);
        System.out.println("Number of mutators with 1 lines: " + mutatorsLinesOne);
        System.out.println("Number of mutators with 2 lines: " + mutatorsLinesTwo);
        System.out.println("Number of mutators with 3 lines: " + mutatorsLinesThree);
        System.out.println("Number of mutators with 4 lines: " + mutatorsLinesFour);
        System.out.println("Number of mutators with 5 lines: " + mutatorsLinesFive);
        System.out.println("Number of mutators with 6 lines: " + mutatorsLinesSix);
        System.out.println("Number of mutators with 7 lines: " + mutatorsLinesSeven);
        System.out.println("Number of mutators with 8 lines: " + mutatorsLinesEight);
        System.out.println("Number of mutators with 9 lines: " + mutatorsLinesNine);
        System.out.println("Number of mutators with 10+ lines: " + mutatorsLinesTenOrMore);
        
        System.out.println("\nNUMBER OF LINES IN STATIC METHODS");
        System.out.println("Number of static methods with 0 lines: " + staticMethodsLinesZero);
        System.out.println("Number of static methods with 1 lines: " + staticMethodsLinesOne);
        System.out.println("Number of static methods with 2 lines: " + staticMethodsLinesTwo);
        System.out.println("Number of static methods with 3 lines: " + staticMethodsLinesThree);
        System.out.println("Number of static methods with 4 lines: " + staticMethodsLinesFour);
        System.out.println("Number of static methods with 5 lines: " + staticMethodsLinesFive);
        System.out.println("Number of static methods with 6 lines: " + staticMethodsLinesSix);
        System.out.println("Number of static methods with 7 lines: " + staticMethodsLinesSeven);
        System.out.println("Number of static methods with 8 lines: " + staticMethodsLinesEight);
        System.out.println("Number of static methods with 9 lines: " + staticMethodsLinesNine);
        System.out.println("Number of static methods with 10+ lines: " + staticMethodsLinesTenOrMore);
        
        System.out.println("\nNUMBER OF LINES IN INSTANCE METHODS");
        System.out.println("Number of instance methods with 0 lines: " + instanceMethodsLinesZero);
        System.out.println("Number of instance methods with 1 lines: " + instanceMethodsLinesOne);
        System.out.println("Number of instance methods with 2 lines: " + instanceMethodsLinesTwo);
        System.out.println("Number of instance methods with 3 lines: " + instanceMethodsLinesThree);
        System.out.println("Number of instance methods with 4 lines: " + instanceMethodsLinesFour);
        System.out.println("Number of instance methods with 5 lines: " + instanceMethodsLinesFive);
        System.out.println("Number of instance methods with 6 lines: " + instanceMethodsLinesSix);
        System.out.println("Number of instance methods with 7 lines: " + instanceMethodsLinesSeven);
        System.out.println("Number of instance methods with 8 lines: " + instanceMethodsLinesEight);
        System.out.println("Number of instance methods with 9 lines: " + instanceMethodsLinesNine);
        System.out.println("Number of instance methods with 10+ lines: " + instanceMethodsLinesTenOrMore);
        

        System.out.println("\nMEMBER PERMISSION COUNT:");
        System.out.println("Number of public fields: " + numPublicPermissionField);
        System.out.println("Number of protected fields: " + numProtectedPermissionField);
        System.out.println("Number of private fields: " + numPrivatePermissionField);
        System.out.println("Number of default fields: " + numDefaultPermissionField);
        System.out.println("Number of public methods: " + numPublicPermissionMethod);
        System.out.println("Number of protected methods: " + numProtectedPermissionMethod);
        System.out.println("Number of private methods: " + numPrivatePermissionMethod);
        System.out.println("Number of default methods: " + numDefaultPermissionMethod);

        System.out.println("\nNUMBER OF MEMBERS IN CLASS:");
        System.out.println("Number of fields: " + numFieldsMember);
        System.out.println("Number of methods: " + numMethodsMember);
        System.out.println("Total number of members: " + (numFieldsMember + numMethodsMember));
        
        System.out.println("\nNUMBER OF INHERITED CLASSES:");
        System.out.println("Number of classes: " + classCounter);
        System.out.println("Number of classes that use inheritance: " + inheritanceCounter);
        System.out.println("Number of classes that use interfaces: " + interfaceCounter);
        System.out.println("Number of classes that use both: " + inheritanceAndInterfaceCounter);

        System.out.println("\nNUMBER OF RECURSIVE + NON-RECURSIVE CALLS:");
        System.out.println("Number of recursive calls: " + globalRecursiveCount);
        System.out.println("Number of non-recursive calls: " + globalNonRecursiveCount);

        System.out.println("\nNUMBER OF EXCEPTIONS THROWN:");
        System.out.println("Custom exceptions thrown: " + customExceptionsThrown);
        System.out.println("JRE exceptions thrown: " + jreExceptionsThrown);
        System.out.println("Generic exceptions thrown: " + genericExceptionsThrown);
        
        System.out.println("\nNUMBER OF EXCEPTIONS CAUGHT:");
        System.out.println("Generic exceptions caught: " + genericExceptionCaughtCount);
        System.out.println("JRE-defined exceptions caught: " + jreExceptionCaughtCount);
        System.out.println("Custom exceptions caught: " + customExceptionCaughtCount);
        
        System.out.println("\nTOTAL LINE COUNT:");
        System.out.println("Lines read: " + globallineCount);
    }
}
